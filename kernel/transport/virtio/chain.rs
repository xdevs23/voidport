// SPDX-License-Identifier: GPL-2.0
//! The chains of a channel: the pages each lists, from the moment it is
//! built until the device returns it, and where the returned ones wait for
//! the connection that reads them.

use core::cell::Cell;

use kernel::bindings;
use kernel::page::{Page, PAGE_SIZE};
use kernel::prelude::*;
use kernel::sync::{new_condvar, new_mutex, Arc, CondVar, Mutex};
use voidport_bindings as generated;
use voidport_proto::chain::{ChainHead, ChainId, ChainKind, ChannelNumber, CHAIN_HEAD_LEN};

use super::Wait;
use crate::part::Part;
use crate::wire::Source;

/// A reference to a page, given back when it is dropped.
struct Held(*mut bindings::page);

impl Held {
    /// # Safety
    ///
    /// `page` is in memory, and the kernel counts its references.
    unsafe fn new(page: *mut bindings::page) -> Self {
        // SAFETY: `page` is in memory, and the kernel counts its references,
        // as the caller promises.
        unsafe { generated::voidport_get_page(page) };
        Self(page)
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // SAFETY: this value has a reference to the page.
        unsafe { generated::voidport_put_page(self.0) };
    }
}

/// Which part of a chain bytes belong to.
#[derive(Clone, Copy)]
enum Side {
    /// The part the device reads.
    Readable,
    /// The part the device writes.
    Writable,
}

/// Bytes inside one page that a chain lists.
struct Named {
    page: *mut bindings::page,
    offset: usize,
    len: usize,
}

/// A chain, and everything it lists, while it is built, while the device has
/// it, and once it is returned.
pub(super) struct Flight {
    /// The channel the device returns the chain to, from the moment the
    /// device has it until it returns it.
    pub(super) mailbox: Option<Arc<Mailbox>>,
    id: ChainId,
    kind: ChainKind,
    /// The pages the chain owns: those of the head and the frame, then those
    /// of the reply area, then the copies of data from kernel memory.
    owned: KVec<Page>,
    /// How many of the owned pages contain the head and the frame.
    sent: usize,
    reply_len: usize,
    /// A reference to each page of data the chain lists.
    held: KVec<Held>,
    /// The parts the device reads: the head, the frame and the data of a
    /// write.
    readable: KVec<Named>,
    /// The parts the device writes: the reply area and the data area, for
    /// the data of a read.
    writable: KVec<Named>,
    /// One scatterlist entry for each part.
    sg: KVec<bindings::scatterlist>,
    /// How many bytes the device wrote, once it returned the chain.
    pub(super) written: u32,
    /// The chain returned before this one, while both wait for the
    /// connection.
    next: Option<KBox<Flight>>,
}

// SAFETY: the pages a flight lists are owned by it or referenced by it, and
// are not tied to the task that built it. Its scatterlist is used only by the
// task that makes it available, under the lock of the queue.
unsafe impl Send for Flight {}

impl Flight {
    fn closes(&self) -> bool {
        self.kind == ChainKind::Close
    }

    /// Lists `len` bytes from `offset` on in `page` on `side` of the chain.
    fn name(&mut self, side: Side, page: *mut bindings::page, offset: usize, len: usize) -> Result {
        self.sg.push(pin_init::zeroed(), GFP_KERNEL)?;
        let parts = match side {
            Side::Readable => &mut self.readable,
            Side::Writable => &mut self.writable,
        };
        parts.push(Named { page, offset, len }, GFP_KERNEL)?;
        Ok(())
    }

    /// Copies `bytes` into the owned pages, from the byte `at` of the first.
    fn copy_in(&self, mut at: usize, mut bytes: &[u8]) -> Result {
        while !bytes.is_empty() {
            let offset = at % PAGE_SIZE;
            let len = (PAGE_SIZE - offset).min(bytes.len());
            // SAFETY: `bytes` has at least `len` bytes, which fit the page
            // from `offset` on.
            unsafe { self.owned[at / PAGE_SIZE].write_raw(bytes.as_ptr(), offset, len) }?;
            bytes = &bytes[len..];
            at += len;
        }
        Ok(())
    }

    /// Copies the bytes of the reply area from `at` on into `into`.
    fn copy_out(&self, mut at: usize, into: &mut [u8]) -> Result {
        let mut done = 0;
        while done < into.len() {
            let offset = at % PAGE_SIZE;
            let len = (PAGE_SIZE - offset).min(into.len() - done);
            let page = &self.owned[self.sent + at / PAGE_SIZE];
            // SAFETY: `into` has room for `len` bytes from `done` on, and the
            // reply area has them in this page from `offset` on.
            unsafe { page.read_raw(into.as_mut_ptr().add(done), offset, len) }?;
            done += len;
            at += len;
        }
        Ok(())
    }

    /// The scatterlist of the readable parts and the one of the writable
    /// parts, set up for the device, and how many lists are writable.
    pub(super) fn scatter(&mut self) -> ([*mut bindings::scatterlist; 2], c_uint) {
        let readable = self.sg.as_mut_ptr();
        // SAFETY: the scatterlist has an entry for every part, the readable
        // ones first.
        let writable = unsafe { readable.add(self.readable.len()) };
        // SAFETY: as above, and each part lies inside its page.
        unsafe {
            set_up(readable, &self.readable);
            set_up(writable, &self.writable);
        }
        (
            [readable, writable],
            c_uint::from(!self.writable.is_empty()),
        )
    }
}

/// Makes the `parts.len()` entries at `sg` one terminated list of `parts`.
///
/// # Safety
///
/// `sg` has room for an entry for every part, and every part lies inside a
/// page in memory.
unsafe fn set_up(sg: *mut bindings::scatterlist, parts: &[Named]) {
    if parts.is_empty() {
        return;
    }
    // SAFETY: `sg` and the parts are as the caller promises. A part lies
    // inside a page, so its length and its offset fit.
    unsafe {
        bindings::sg_init_table(sg, parts.len() as c_uint);
        for (index, part) in parts.iter().enumerate() {
            generated::voidport_sg_set_page(
                sg.add(index),
                part.page,
                part.len as c_uint,
                part.offset as c_uint,
            );
        }
    }
}

/// A descriptor chain before the device has it.
pub struct Chain(pub(super) KBox<Flight>);

impl Chain {
    /// The chain `id` of `kind` on `channel` that contains `frame` and
    /// `reply_len` bytes of reply area. The head and the frame fill pages
    /// allocated for the chain, and the reply area fills further ones.
    pub(super) fn new(
        id: ChainId,
        channel: ChannelNumber,
        kind: ChainKind,
        frame: &[u8],
        reply_len: usize,
    ) -> Result<Self> {
        let room = u32::try_from(reply_len).map_err(|_| EOVERFLOW)?;
        let head = ChainHead::new(channel, kind, room);
        let sent_len = CHAIN_HEAD_LEN + frame.len();
        let sent = sent_pages(frame.len());
        let pages = Self::fixed_descriptors(frame.len(), reply_len);
        let mut flight = KBox::new(
            Flight {
                mailbox: None,
                id,
                kind,
                owned: KVec::with_capacity(pages, GFP_KERNEL)?,
                sent,
                reply_len,
                held: KVec::new(),
                readable: KVec::new(),
                writable: KVec::new(),
                sg: KVec::new(),
                written: 0,
                next: None,
            },
            GFP_KERNEL,
        )?;
        for _ in 0..pages {
            flight
                .owned
                .push(Page::alloc_page(GFP_KERNEL)?, GFP_KERNEL)?;
        }
        flight.copy_in(0, &head.encode())?;
        flight.copy_in(CHAIN_HEAD_LEN, frame)?;
        for (index, len) in in_pages(sent_len).enumerate() {
            let page = flight.owned[index].as_ptr();
            flight.name(Side::Readable, page, 0, len)?;
        }
        for (index, len) in in_pages(reply_len).enumerate() {
            let page = flight.owned[sent + index].as_ptr();
            flight.name(Side::Writable, page, 0, len)?;
        }
        Ok(Self(flight))
    }

    /// How many descriptors the head, a frame of `frame_len` bytes and a
    /// reply area of `reply_len` bytes use in a chain: one for each page they
    /// fill.
    pub(super) fn fixed_descriptors(frame_len: usize, reply_len: usize) -> usize {
        sent_pages(frame_len) + reply_len.div_ceil(PAGE_SIZE)
    }

    /// The number of the chain on the channel it belongs to.
    pub fn id(&self) -> ChainId {
        self.0.id
    }

    /// How many descriptors the chain uses.
    pub fn descriptors(&self) -> usize {
        self.0.readable.len() + self.0.writable.len()
    }

    /// Adds `part` after the frame, for the device to read: data of a
    /// write. The chain has a reference to the page of the part until the
    /// chain is dropped, or contains a copy of a part of kernel memory, whose
    /// page may have no count of references.
    pub fn data(&mut self, part: &Part) -> Result {
        // An empty part adds no descriptor.
        if part.is_empty() {
            return Ok(());
        }
        if part.counted() {
            return self.hold(Side::Readable, part);
        }
        let page = Page::alloc_page(GFP_KERNEL)?;
        part.map(|bytes| {
            // SAFETY: `map` maps the bytes of the part for the call, and they
            // fit a page.
            unsafe { page.write_raw(bytes, 0, part.len()) }
        })?;
        let named = page.as_ptr();
        self.0.owned.push(page, GFP_KERNEL)?;
        self.0.name(Side::Readable, named, 0, part.len())
    }

    /// Adds `part` to the data area after the reply area, for the device to
    /// write the data of a read into. The chain has a reference to the page
    /// of the part until the chain is dropped. `EINVAL` for a part of kernel
    /// memory, whose page may have no count of references.
    pub fn read_into(&mut self, part: &Part) -> Result {
        if !part.counted() {
            return Err(EINVAL);
        }
        if part.is_empty() {
            return Ok(());
        }
        self.hold(Side::Writable, part)
    }

    fn hold(&mut self, side: Side, part: &Part) -> Result {
        let (page, offset) = part.page_of();
        self.0.held.reserve(1, GFP_KERNEL)?;
        self.0.name(side, page, offset, part.len())?;
        // SAFETY: the page of a counted part is not freed while the part
        // exists, and the reference prevents freeing it afterwards.
        let held = unsafe { Held::new(page) };
        // The space was reserved above, so the push does not allocate.
        self.0.held.push_within_capacity(held).map_err(|_| ENOMEM)
    }
}

/// How many pages the head of a chain and a frame of `frame_len` bytes fill.
fn sent_pages(frame_len: usize) -> usize {
    (CHAIN_HEAD_LEN + frame_len).div_ceil(PAGE_SIZE)
}

/// The length of the part of each page that `len` bytes fill, from the start
/// of the first page.
fn in_pages(len: usize) -> impl Iterator<Item = usize> {
    (0..len.div_ceil(PAGE_SIZE)).map(move |index| (len - index * PAGE_SIZE).min(PAGE_SIZE))
}

/// A chain the device returned, with what it wrote into it.
pub struct Returned(KBox<Flight>);

impl Returned {
    /// The number of the chain on the channel it belongs to.
    pub fn id(&self) -> ChainId {
        self.0.id
    }

    /// How many bytes the device wrote into the reply area and the data area
    /// together.
    pub fn written(&self) -> usize {
        self.0.written as usize
    }

    /// How many bytes the data area after the reply area has.
    pub fn data_area_len(&self) -> usize {
        let writable: usize = self.0.writable.iter().map(|named| named.len).sum();
        writable - self.0.reply_len
    }

    /// The bytes the device wrote into the reply area, read from its start.
    pub fn reply(&self) -> Reply<'_> {
        Reply {
            flight: &self.0,
            at: Cell::new(0),
            end: self.written().min(self.0.reply_len),
        }
    }
}

/// The reply area of a returned chain, as a source of the bytes the device
/// wrote into it.
pub struct Reply<'a> {
    flight: &'a Flight,
    at: Cell<usize>,
    end: usize,
}

impl Reply<'_> {
    /// How many bytes were read.
    pub fn consumed(&self) -> usize {
        self.at.get()
    }

    /// Whether every byte the device wrote into the reply area was read.
    pub fn is_empty(&self) -> bool {
        self.at.get() == self.end
    }

    /// The position after the next `len` bytes, or `EPIPE` when the device
    /// wrote fewer.
    fn advance(&self, len: usize) -> Result<usize> {
        self.at
            .get()
            .checked_add(len)
            .filter(|&end| end <= self.end)
            .ok_or(EPIPE)
    }
}

impl Source for Reply<'_> {
    fn receive_exact(&self, buf: &mut [u8]) -> Result {
        let end = self.advance(buf.len())?;
        self.flight.copy_out(self.at.get(), buf)?;
        self.at.set(end);
        Ok(())
    }

    fn discard(&self, len: usize) -> Result {
        let end = self.advance(len)?;
        self.at.set(end);
        Ok(())
    }
}

/// Where the device returns the chains of one channel.
#[pin_data]
pub(super) struct Mailbox {
    #[pin]
    post: Mutex<Post>,
    #[pin]
    changed: CondVar,
}

struct Post {
    /// The returned chains, the last one first.
    returned: Option<KBox<Flight>>,
    /// How many chains other than the close chain the device has.
    in_flight: usize,
    /// Whether the device has returned a chain of the channel. The first
    /// chain of a channel is the hello, and no chain follows it before it
    /// returns.
    opened: bool,
    /// The number of the last chain built.
    built: u64,
    shut: bool,
    /// The close chain, until it is made available.
    close: Option<Chain>,
}

impl Post {
    /// The close chain, once the channel is shut and the close cannot
    /// overtake the hello: the hello has returned, or the device has no chain
    /// of the channel. The server ends the chains of a channel it closes, so a
    /// close after the hello never waits for them.
    fn due(&mut self) -> Option<Chain> {
        if self.shut && (self.opened || self.in_flight == 0) {
            self.close.take()
        } else {
            None
        }
    }
}

impl Drop for Post {
    fn drop(&mut self) {
        // One at a time, so a long list does not recurse.
        let mut next = self.returned.take();
        while let Some(mut flight) = next {
            next = flight.next.take();
        }
    }
}

impl Mailbox {
    pub(super) fn new() -> Result<Arc<Self>> {
        Arc::pin_init(
            pin_init!(Self {
                post <- new_mutex!(Post {
                    returned: None,
                    in_flight: 0,
                    opened: false,
                    built: 0,
                    shut: false,
                    close: None,
                }, "voidport::mailbox"),
                changed <- new_condvar!("voidport::returned"),
            }),
            GFP_KERNEL,
        )
    }

    /// A number no other chain of the channel has.
    pub(super) fn next_id(&self) -> ChainId {
        let mut post = self.post.lock();
        post.built += 1;
        ChainId(post.built)
    }

    /// Stores `close`, the close chain of the channel, until it is due.
    pub(super) fn keep_close(&self, close: Chain) {
        self.post.lock().close = Some(close);
    }

    /// Counts `chain`, which the device has from now on until it returns it.
    /// `ENOTCONN` for a chain other than the close chain once the channel is
    /// shut.
    pub(super) fn count(&self, chain: &Chain) -> Result {
        if chain.0.closes() {
            return Ok(());
        }
        let mut post = self.post.lock();
        if post.shut {
            return Err(crate::errno::enotconn());
        }
        post.in_flight += 1;
        Ok(())
    }

    /// Undoes the count of `flight`, which the queue did not accept after
    /// all, and returns the close chain when it is due now.
    pub(super) fn uncount(&self, flight: &Flight) -> Option<Chain> {
        if flight.closes() {
            return None;
        }
        let mut post = self.post.lock();
        post.in_flight -= 1;
        let due = post.due();
        drop(post);
        self.changed.notify_all();
        due
    }

    /// Hands `flight`, which the device returned, to the channel, and returns
    /// the close chain when it is due now. A returned close chain is dropped.
    pub(super) fn deliver(&self, mut flight: KBox<Flight>) -> Option<Chain> {
        if flight.closes() {
            return None;
        }
        let mut post = self.post.lock();
        post.in_flight -= 1;
        post.opened = true;
        flight.next = post.returned.take();
        post.returned = Some(flight);
        let due = post.due();
        drop(post);
        self.changed.notify_all();
        due
    }

    /// Shuts the channel, and returns the close chain when it is due now.
    pub(super) fn shut(&self) -> Option<Chain> {
        let mut post = self.post.lock();
        post.shut = true;
        let due = post.due();
        drop(post);
        self.changed.notify_all();
        due
    }

    /// Waits until the device has returned every chain it has. A signal ends
    /// the wait.
    pub(super) fn wait_idle(&self) -> Result {
        let mut post = self.post.lock();
        while post.in_flight != 0 {
            if self.changed.wait_interruptible(&mut post) {
                return Err(ERESTARTSYS);
            }
        }
        Ok(())
    }

    /// The next chain that the device returned, with the wait for one given
    /// by `wait`. `None` once the channel is shut and the device has returned
    /// every chain of it.
    pub(super) fn next(&self, wait: Wait) -> Result<Option<Returned>> {
        let mut post = self.post.lock();
        loop {
            if let Some(mut flight) = post.returned.take() {
                post.returned = flight.next.take();
                return Ok(Some(Returned(flight)));
            }
            if post.shut && post.in_flight == 0 {
                return Ok(None);
            }
            match wait {
                Wait::Interruptible => {
                    if self.changed.wait_interruptible(&mut post) {
                        return Err(ERESTARTSYS);
                    }
                }
                Wait::Always => self.changed.wait(&mut post),
            }
        }
    }
}
