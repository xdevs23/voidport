// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use kernel::sync::{new_condvar, new_mutex, Arc, CondVar, Mutex};
use voidport_proto::chain::ChainId;
use voidport_proto::frame::{FrameHeader, FrameKind, FRAME_HEADER_LEN};
use voidport_proto::opcode::Opcode;
use voidport_session::table::Ticket;

use super::{
    death_of, fill, Arrival, Connection, Death, Ending, Fault, Landing, Link, Outbound, PageData,
    Received, Removed, Reply, Transmit, FORGET_LEN,
};
use crate::virtio::{Chain, Channel, Reply as ChainReply, Returned, Room, Wait};
use crate::wire::{read_header, Caller};

/// A request in a chain that the device has, and where the reply lands,
/// which the reader has from the moment the chain is made available.
struct Carrying {
    chain: ChainId,
    request_id: u64,
    opcode: Opcode,
    reply: Arc<Reply>,
    landing: Landing,
}

impl Carrying {
    fn into_removed(self) -> Removed {
        Removed {
            request_id: self.request_id,
            opcode: self.opcode,
            reply: self.reply,
            landing: Some(self.landing),
        }
    }
}

struct Flights {
    /// The request whose chain the device has. The pool lends a connection to
    /// one request at a time.
    request: Option<Carrying>,
    /// The number of the chain of the forget that waits until the device
    /// returns it.
    forget: Option<ChainId>,
    /// Why the connection ended, once [`Link::end`] recorded it.
    ended: Option<Death>,
}

/// A channel of a virtio device, and the chains of the connection on it.
///
/// Every chain is made available under the lock of `flights`, which the end
/// of the connection acquires too, so a chain is made available only on a
/// connection that lives. The lock of `flights` is acquired before the lock
/// of the state of the connection.
#[pin_data]
pub(super) struct ChannelLink {
    channel: Channel,
    #[pin]
    flights: Mutex<Flights>,
    /// Notified when the chain of a forget returns, and when the connection
    /// ends.
    #[pin]
    returned: CondVar,
}

enum Carried {
    Available,
    /// The connection is dead, and the claim of the request is retired.
    Refused,
    /// The connection died with the reply of the request armed, which the
    /// death path ends.
    Lost,
}

impl ChannelLink {
    pub(super) fn new(channel: Channel) -> impl PinInit<Self> {
        pin_init!(Self {
            channel,
            flights <- new_mutex!(Flights {
                request: None,
                forget: None,
                ended: None,
            }, "voidport::flights"),
            returned <- new_condvar!("voidport::chain_returned"),
        })
    }

    /// The chain of `request`: its frame, the room for its reply, and the
    /// parts of its data, which the device reads for a write and fills for a
    /// read.
    fn chain_of(&self, request: &Outbound<'_>) -> Result<Chain> {
        let mut chain = self.channel.frame(request.frame, request.reply_len)?;
        match request.data {
            PageData::None => {}
            PageData::Write(_) => request.parts(|part| chain.data(part))?,
            PageData::Read(_) => request.parts(|part| chain.read_into(part))?,
        }
        Ok(chain)
    }

    /// Arms `reply` with `ticket`, hands its landing to the reader and makes
    /// `chain` available in `room`, all under the locks of the flights and of
    /// the state of `connection`, which the death of the connection
    /// acquires too.
    fn carry(
        &self,
        connection: &Connection,
        room: Room<'_>,
        ticket: &mut Ticket,
        chain: Chain,
        reply: &Arc<Reply>,
    ) -> Carried {
        let mut flights = self.flights.lock();
        let mut state = connection.state.lock();
        if state.death.is_some() {
            // Connection burial has already retired the claim.
            return Carried::Refused;
        }
        let refusal = if flights.request.is_some() {
            Some("two requests in flight on one channel")
        } else if !state.arm(ticket, reply.clone()) {
            Some("a request lost its claim before transmission")
        } else {
            None
        };
        if let Some(refusal) = refusal {
            drop(state);
            drop(flights);
            drop(room);
            connection.bury(Death::Local(refusal));
            return Carried::Refused;
        }
        let Some(landing) = reply.begin_fill() else {
            drop(state);
            drop(flights);
            drop(room);
            connection.bury(Death::Local("a request lost its waiting storage"));
            return Carried::Lost;
        };
        state.carried = true;
        let id = chain.id();
        if let Err(error) = room.make_available(chain) {
            drop(state);
            reply.abort_fill(Some(landing));
            drop(flights);
            connection.bury(Death::Transport(error));
            return Carried::Lost;
        }
        drop(state);
        flights.request = Some(Carrying {
            chain: id,
            request_id: ticket.request_id(),
            opcode: ticket.opcode(),
            reply: reply.clone(),
            landing,
        });
        Carried::Available
    }

    /// Removes the request or the forget that `returned` was made available
    /// for from the flights, and reads the reply in it. `None` when it contains no
    /// message for the reader to report: the chain of a forget, or one of a
    /// connection that ended.
    fn take_returned(&self, connection: &Connection, returned: Returned) -> Option<Received> {
        let mut flights = self.flights.lock();
        if flights.forget == Some(returned.id()) {
            flights.forget = None;
            drop(flights);
            self.returned.notify_all();
            return None;
        }
        let ours = flights
            .request
            .as_ref()
            .is_some_and(|carrying| carrying.chain == returned.id());
        let carrying = if ours { flights.request.take() } else { None };
        let ended = flights.ended.is_some();
        drop(flights);
        let Some(carrying) = carrying else {
            connection.bury(Death::Local(
                "a chain returned that no request made available",
            ));
            return None;
        };
        if ended {
            // The death removed the request from the table and left the
            // reply to the reader.
            connection.settle_removed(carrying.into_removed());
            return None;
        }
        Self::answer_chain(connection, &returned, carrying)
    }

    /// Reads the reply in `returned` for the request of `carrying`, and
    /// hands it to the request. `None` when the connection ended over it.
    fn answer_chain(
        connection: &Connection,
        returned: &Returned,
        carrying: Carrying,
    ) -> Option<Received> {
        // The device returns a chain with nothing written on a channel that
        // is not open.
        if returned.written() == 0 {
            let death = Death::Transport(crate::errno::econnreset());
            return Self::end_unanswered(connection, death, carrying);
        }
        let source = returned.reply();
        let mut header = [0u8; FRAME_HEADER_LEN];
        let head = match read_header(&source, &mut header) {
            Ok(true) => FrameHeader::parse(&header)
                .and_then(|head| head.validate().map(|()| head))
                .map_err(|fault| Death::Protocol(Fault::Framing(fault))),
            Ok(false) => Err(Death::Transport(crate::errno::econnreset())),
            Err(error) => Err(death_of(error)),
        };
        let head = match head {
            Ok(head) => head,
            Err(death) => return Self::end_unanswered(connection, death, carrying),
        };
        if head.kind() != FrameKind::Response || head.request_id.get() != carrying.request_id {
            let death = Death::Protocol(Fault::Link(
                "a chain returned with a message that is not the reply to its request",
            ));
            return Self::end_unanswered(connection, death, carrying);
        }
        // The table returns the reply that `carrying` has.
        if let Err((death, _)) = connection.route(carrying.request_id, head.opcode.get()) {
            connection.lose(death, carrying.into_removed());
            return None;
        }
        let Carrying {
            request_id,
            opcode,
            reply,
            mut landing,
            ..
        } = carrying;
        let filled = fill_chain(returned, &source, &header, &mut landing).and_then(|()| {
            reply
                .validate(landing.bytes())
                .map_err(|fault| Death::Protocol(Fault::Framing(fault)))
        });
        if let Err(death) = filled {
            let removed = Removed {
                request_id,
                opcode,
                reply,
                landing: Some(landing),
            };
            connection.lose(death, removed);
            return None;
        }
        Some(reply.end_fill(landing))
    }

    /// Ends `connection` with `death` over the chain of `carrying`, whose
    /// request is in the table unless a death removed it meanwhile, and ends
    /// its reply the way it leaves the table.
    fn end_unanswered(
        connection: &Connection,
        death: Death,
        carrying: Carrying,
    ) -> Option<Received> {
        let state = connection.state.lock();
        if state.death.is_some() {
            drop(state);
            connection.settle_removed(carrying.into_removed());
            return None;
        }
        // The burial of the table ends the reply, which waits again.
        carrying.reply.abort_fill(Some(carrying.landing));
        drop(state);
        connection.bury(death);
        None
    }
}

impl Link for ChannelLink {
    fn data_room(&self, frame_len: usize, reply_len: usize) -> Result<Option<usize>> {
        self.channel.data_room(frame_len, reply_len).map(Some)
    }

    /// A signal ends the wait for room on the queue and cancels the request:
    /// nothing of it reached the device. The chain is [`Transmit::Written`]
    /// once the device has it.
    fn transmit(
        &self,
        connection: &Connection,
        ticket: &mut Ticket,
        request: &Outbound<'_>,
        reply: Arc<Reply>,
    ) -> Transmit {
        if kernel::current!().signal_pending() {
            connection.abandon_claim(ticket);
            return Transmit::Cancelled;
        }
        let chain = match self.chain_of(request) {
            Ok(chain) => chain,
            Err(error) => {
                connection.abandon_claim(ticket);
                return Transmit::Failed(error);
            }
        };
        let room = match self.channel.room(chain.descriptors(), Wait::Interruptible) {
            Ok(room) => room,
            Err(error) => {
                connection.abandon_claim(ticket);
                if error == ERESTARTSYS {
                    return Transmit::Cancelled;
                }
                connection.bury(Death::Transport(error));
                return Transmit::Dead;
            }
        };
        match self.carry(connection, room, ticket, chain, &reply) {
            Carried::Available => Transmit::Written,
            Carried::Refused | Carried::Lost => Transmit::Dead,
        }
    }

    fn send_callerless(
        &self,
        connection: &Connection,
        mut ticket: Ticket,
        frame: &[u8],
        reply: Arc<Reply>,
    ) -> Result {
        let chain = match reply
            .reply_area()
            .and_then(|area| self.channel.frame(frame, area))
        {
            Ok(chain) => chain,
            Err(error) => {
                connection.abandon(ticket);
                return Err(error);
            }
        };
        // The cleanup waits for room as it waits for a stream to accept a
        // frame: no signal ends the wait.
        let room = match self.channel.room(chain.descriptors(), Wait::Always) {
            Ok(room) => room,
            Err(error) => {
                connection.abandon(ticket);
                connection.bury(Death::Transport(error));
                return Err(EIO);
            }
        };
        match self.carry(connection, room, &mut ticket, chain, &reply) {
            // The table owns completion, also after a death.
            Carried::Available | Carried::Lost => Ok(()),
            Carried::Refused => Err(EIO),
        }
    }

    /// Makes the chain of the forget available, and waits until the device
    /// returned it or the connection ended, so a reply still shows that the
    /// server read every forget sent before the request of that reply.
    fn forget(
        &self,
        connection: &Connection,
        caller: Caller,
        node_id: u64,
        nlookup: u64,
    ) -> Result {
        let mut frame = [0u8; FORGET_LEN];
        let (request_id, frame) = connection.record_forget(caller, node_id, nlookup, &mut frame)?;
        // A forget has no reply.
        let chain = match self.channel.frame(frame, 0) {
            Ok(chain) => chain,
            Err(error) => return connection.withdraw_unsent_forget(request_id, error),
        };
        let room = match self.channel.room(chain.descriptors(), Wait::Always) {
            Ok(room) => room,
            Err(error) => {
                connection.bury(Death::Transport(error));
                return connection.withdraw_unsent_forget(request_id, EIO);
            }
        };
        let id = chain.id();
        let mut flights = self.flights.lock();
        if flights.ended.is_some() {
            drop(flights);
            drop(room);
            return connection.withdraw_unsent_forget(request_id, EIO);
        }
        if let Err(error) = room.make_available(chain) {
            drop(flights);
            connection.bury(Death::Transport(error));
            return connection.withdraw_unsent_forget(request_id, EIO);
        }
        flights.forget = Some(id);
        // A death leaves the forget to the settling of the loss.
        while flights.forget == Some(id) && flights.ended.is_none() {
            self.returned.wait(&mut flights);
        }
        Ok(())
    }

    /// No signal ends the wait: until the device returned a chain, it may
    /// write into the pages of the landing, and it returns every chain.
    fn receive(&self, connection: &Connection) -> core::result::Result<Received, Death> {
        while let Ok(Some(returned)) = self.channel.next(Wait::Always) {
            if let Some(received) = self.take_returned(connection, returned) {
                return Ok(received);
            }
        }
        // The end of the connection shut the channel, and the device returned
        // every chain of it.
        let mut flights = self.flights.lock();
        loop {
            if let Some(death) = flights.ended {
                return Err(death);
            }
            self.returned.wait(&mut flights);
        }
    }

    /// Settles every chain the device returns after the connection ended,
    /// until it returned all of them or a signal ends the wait.
    fn drain(&self, connection: &Connection) -> Result {
        while let Some(returned) = self.channel.next(Wait::Interruptible)? {
            // A connection that ended reports no reply to anyone.
            drop(self.take_returned(connection, returned));
        }
        Ok(())
    }

    /// Shuts the channel and records the death, either way the connection
    /// ends: the server ends the channel once the device returned every
    /// chain of it. No chain is made available meanwhile, since that needs
    /// the lock of the flights.
    fn end(&self, connection: &Connection, _ending: Ending, death: Death) -> bool {
        let mut flights = self.flights.lock();
        if flights.ended.is_some() {
            return false;
        }
        flights.ended = Some(death);
        self.channel.shut();
        connection.record(death);
        drop(flights);
        self.returned.notify_all();
        true
    }

    fn abort(&self) {
        self.channel.shut();
    }
}

/// Reads the rest of the reply in `returned` from `source`, its reply area
/// after the header read into `header`, into `landing`, the data of a read
/// counted where the device put it, and checks that the reply accounts for
/// every byte the device wrote.
fn fill_chain(
    returned: &Returned,
    source: &ChainReply<'_>,
    header: &[u8; FRAME_HEADER_LEN],
    landing: &mut Landing,
) -> core::result::Result<(), Death> {
    let mut arrival = Arrival::InPlace {
        room: returned.data_area_len(),
        placed: 0,
    };
    fill(source, header, landing, &mut arrival)?;
    let read = source.consumed() + arrival.placed();
    if read != returned.written() {
        return Err(Death::Protocol(Fault::Link(
            "the device wrote another count of bytes into a chain than its reply accounts for",
        )));
    }
    Ok(())
}
