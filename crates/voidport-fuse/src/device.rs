mod attach;

use std::io::{self, IoSlice};
use std::os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::native_endian::{I32, U32, U64};

use crate::abi::{NotifyCode, OutHeader};
use crate::mount::{AutoUnmount, AutoUnmountCopy};
use crate::stop::Stop;

const LAST_STANDARD_STREAM: i32 = 2;

/// The highest errno the kernel takes in a reply: `fuse_dev_do_write` in
/// `fs/fuse/dev.c` (Linux 7.3) fails a reply whose error is -512 or lower
/// with `EINVAL`.
const LAST_ERRNO: i32 = 511;

#[derive(Debug)]
pub(crate) struct Device {
    descriptor: OwnedFd,
    /// Comes after `descriptor`, so that the descriptor is closed before the
    /// socket.
    auto_unmount: Option<AutoUnmount>,
}

impl Device {
    pub(crate) fn open() -> io::Result<Self> {
        let descriptor =
            rustix::fs::open("/dev/fuse", OFlags::RDWR | OFlags::CLOEXEC, Mode::empty())?;
        Self::new(descriptor)
    }

    /// Takes a descriptor of `/dev/fuse`, moved above the standard streams,
    /// where whatever this process writes to a closed stream, such as a log
    /// line, would be sent to the kernel as a reply, and makes its reads
    /// return at once where no request is queued.
    pub(crate) fn new(descriptor: OwnedFd) -> io::Result<Self> {
        let descriptor = above_standard_streams(descriptor)?;
        rustix::io::ioctl_fionbio(&descriptor, true)?;
        Ok(Self {
            descriptor,
            auto_unmount: None,
        })
    }

    pub(crate) fn unmounted_by(self, auto_unmount: AutoUnmount) -> Self {
        Self {
            auto_unmount: Some(auto_unmount),
            ..self
        }
    }

    pub(crate) fn copy_auto_unmount(&self) -> io::Result<Option<AutoUnmountCopy>> {
        self.auto_unmount
            .as_ref()
            .map(AutoUnmount::copy)
            .transpose()
    }

    /// Each descriptor has a separate list of the requests read through it,
    /// and a reply is matched only against the list of the descriptor that
    /// receives it.
    pub(crate) fn clone_connection(&self) -> io::Result<Self> {
        let clone = Self::open()?;
        attach::attach(clone.descriptor.as_fd(), self.descriptor.as_fd())?;
        Ok(clone)
    }

    /// A read that ends without a request is made again: one whose request
    /// the kernel aborted while it was copied, and one that a signal
    /// interrupted. Where no request is queued, this waits for one first.
    pub(crate) fn read(&self, buffer: &mut [u8]) -> Result<usize, Errno> {
        loop {
            match rustix::io::read(&self.descriptor, &mut *buffer) {
                Err(Errno::NOENT | Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    wait(&mut [PollFd::new(&self.descriptor, PollFlags::IN)])?;
                }
                read => return read,
            }
        }
    }

    /// A queued request costs one read. Only where none is queued does this
    /// wait, for a request or for the stop. The kernel takes a queued request
    /// back when the process that waits for it is killed
    /// (`request_wait_answer` in `fs/fuse/dev.c`, Linux 7.2.10), so a read
    /// after the wait can find nothing, and returns at once since the reads
    /// of this descriptor do not wait.
    pub(crate) fn read_unless_stopped(
        &self,
        buffer: &mut [u8],
        stop: &Stop,
    ) -> Result<Option<usize>, Errno> {
        while !stop.is_requested() {
            match rustix::io::read(&self.descriptor, &mut *buffer) {
                Err(Errno::NOENT | Errno::INTR) => {}
                Err(Errno::AGAIN) => wait(&mut [
                    PollFd::new(&stop.pipe(), PollFlags::IN),
                    PollFd::new(&self.descriptor, PollFlags::IN),
                ])?,
                read => return read.map(Some),
            }
        }
        Ok(None)
    }

    pub(crate) fn reply_ok(&self, unique: u64, payload: [&[u8]; 2]) -> Result<(), Errno> {
        self.write(unique, 0, payload)
    }

    /// The kernel takes only errnos from 1 to 511, so anything else is sent as
    /// `EIO`.
    pub(crate) fn reply_error(&self, unique: u64, error: Errno) -> Result<(), Errno> {
        self.write(unique, -reply_errno(error), [&[], &[]])
    }

    pub(crate) fn notify(&self, code: NotifyCode, payload: &[u8]) -> Result<(), Errno> {
        // A notification is a message for request 0, with its code in place of
        // the error.
        self.write(0, code.wire(), [payload, &[]])
    }

    fn write(&self, unique: u64, error: i32, payload: [&[u8]; 2]) -> Result<(), Errno> {
        let length = size_of::<OutHeader>() + payload[0].len() + payload[1].len();
        let header = OutHeader {
            len: U32::new(u32::try_from(length).map_err(|_| Errno::TOOBIG)?),
            error: I32::new(error),
            unique: U64::new(unique),
        };
        let parts = [
            IoSlice::new(header.as_bytes()),
            IoSlice::new(payload[0]),
            IoSlice::new(payload[1]),
        ];
        rustix::io::writev(&self.descriptor, &parts).map(drop)
    }
}

fn wait(ready: &mut [PollFd<'_>]) -> Result<(), Errno> {
    match poll(ready, None) {
        Ok(_) | Err(Errno::INTR) => Ok(()),
        Err(error) => Err(error),
    }
}

/// `descriptor`, moved to a number above the standard streams where it has
/// the number of one, which it only has when that stream was closed. The
/// moved descriptor is closed on `exec`.
pub(crate) fn above_standard_streams(descriptor: OwnedFd) -> io::Result<OwnedFd> {
    if descriptor.as_raw_fd() > LAST_STANDARD_STREAM {
        return Ok(descriptor);
    }
    Ok(rustix::io::fcntl_dupfd_cloexec(
        &descriptor,
        LAST_STANDARD_STREAM + 1,
    )?)
}

fn reply_errno(error: Errno) -> i32 {
    match error.raw_os_error() {
        errno @ 1..=LAST_ERRNO => errno,
        _ => Errno::IO.raw_os_error(),
    }
}

impl From<Device> for OwnedFd {
    fn from(device: Device) -> Self {
        device.descriptor
    }
}

impl AsFd for Device {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Shutdown;
    use std::os::unix::net::UnixDatagram;

    use zerocopy::FromBytes as _;

    use super::*;

    /// A datagram socket separates every message, as the device does. A read
    /// past the last request returns no bytes, which ends every loop that reads
    /// the device.
    pub(crate) fn kernel(requests: &[Vec<u8>]) -> (Device, UnixDatagram) {
        let (ours, theirs) = UnixDatagram::pair().expect("a socket pair");
        for request in requests {
            assert_eq!(
                theirs.send(request).expect("the request is sent"),
                request.len()
            );
        }
        ours.shutdown(Shutdown::Read).expect("the input ends");
        (
            Device {
                descriptor: OwnedFd::from(ours),
                auto_unmount: None,
            },
            theirs,
        )
    }

    pub(crate) fn answer(kernel: &UnixDatagram) -> (OutHeader, Vec<u8>) {
        let mut message = vec![0; 1 << 16];
        let length = kernel.recv(&mut message).expect("a message");
        let (header, payload) = OutHeader::read_from_prefix(&message[..length]).expect("a header");
        assert_eq!(
            header.len.get() as usize,
            length,
            "the header gives the length written"
        );
        (header, payload.to_vec())
    }

    pub(crate) fn discarding() -> Device {
        let null = std::fs::File::options()
            .write(true)
            .open("/dev/null")
            .expect("/dev/null opens");
        Device {
            descriptor: OwnedFd::from(null),
            auto_unmount: None,
        }
    }

    #[test]
    fn a_message_is_one_header_with_the_whole_length_and_the_payload() {
        let (device, kernel) = kernel(&[]);
        device.reply_ok(42, [b"ab", b"cde"]).expect("written");
        let (header, payload) = answer(&kernel);
        assert_eq!(header.len.get(), 21);
        assert_eq!(header.error.get(), 0);
        assert_eq!(header.unique.get(), 42);
        assert_eq!(payload, b"abcde");
    }

    #[test]
    fn an_error_is_the_header_alone_with_the_negative_errno() {
        let (device, kernel) = kernel(&[]);
        device.reply_error(77, Errno::NOENT).expect("written");
        let (header, payload) = answer(&kernel);
        assert_eq!(header.error.get(), -Errno::NOENT.raw_os_error());
        assert_eq!(header.unique.get(), 77);
        assert!(payload.is_empty());
    }

    #[test]
    fn an_errno_outside_what_the_kernel_takes_becomes_eio() {
        for beyond in [512, 4095] {
            assert_eq!(
                reply_errno(Errno::from_raw_os_error(beyond)),
                Errno::IO.raw_os_error()
            );
        }
        assert_eq!(reply_errno(Errno::ACCESS), Errno::ACCESS.raw_os_error());
    }

    #[test]
    fn a_notification_is_a_message_for_request_zero_with_its_code() {
        let (device, kernel) = kernel(&[]);
        device.notify(NotifyCode::Resend, &[]).expect("written");
        let (header, payload) = answer(&kernel);
        assert_eq!(
            (header.unique.get(), header.error.get()),
            (0, NotifyCode::Resend.wire())
        );
        assert!(payload.is_empty());
    }

    #[test]
    fn a_descriptor_above_the_standard_streams_is_not_moved() {
        let (ours, _theirs) = UnixDatagram::pair().expect("a socket pair");
        let descriptor = OwnedFd::from(ours);
        let number = descriptor.as_raw_fd();
        assert!(number > LAST_STANDARD_STREAM);
        let returned = above_standard_streams(descriptor).expect("not moved");
        assert_eq!(returned.as_raw_fd(), number);
    }

    #[test]
    fn a_descriptor_whose_reads_do_not_wait_waits_for_the_next_request() {
        let (ours, theirs) = UnixDatagram::pair().expect("a socket pair");
        ours.set_nonblocking(true).expect("reads do not wait");
        let device = Device {
            descriptor: OwnedFd::from(ours),
            auto_unmount: None,
        };
        std::thread::scope(|scope| {
            scope.spawn(|| theirs.send(b"request").expect("sent"));
            assert_eq!(device.read(&mut [0; 16]), Ok(7));
        });
    }
}
