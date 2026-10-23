// SPDX-License-Identifier: GPL-2.0

use kernel::prelude::*;
use kernel::sync::{new_condvar, new_mutex, Arc, CondVar, Mutex};
use voidport_proto::frame::{FrameHeader, FrameKind, FRAME_HEADER_LEN};
use voidport_session::table::Ticket;

use super::{
    death_of, fill, Arrival, Connection, Death, Ending, Fault, Link, Outbound, PageData, Received,
    Removed, Reply, Transmit, FORGET_LEN,
};
use crate::part::Part;
use crate::socket::Stream;
use crate::wire::{drain_message, read_header, Caller};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sending {
    Idle,
    Frame,
    /// A clean close found a frame being written. The sending direction is
    /// shut once that frame ends.
    EndsAfterFrame,
    /// Sending has ended, and the socket is shut as the ending required.
    Ended,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SendMode {
    /// Any signal ends the wait of a caller.
    Foreground,
    /// The cleanup waits until the socket shuts down.
    Cleanup,
}

#[pin_data]
pub(super) struct StreamLink {
    stream: Stream,
    /// The single serialization point of the stream: every frame is written
    /// while it is held, so two frames never interleave on the socket.
    #[pin]
    send: Mutex<Sending>,
    #[pin]
    send_ready: CondVar,
}

struct Sender<'a>(&'a StreamLink);

impl Drop for Sender<'_> {
    fn drop(&mut self) {
        let mut send = self.0.send.lock();
        *send = match *send {
            Sending::Frame => Sending::Idle,
            Sending::EndsAfterFrame => {
                self.0.stream.shutdown_send();
                Sending::Ended
            }
            ended => ended,
        };
        drop(send);
        self.0.send_ready.notify_all();
    }
}

impl StreamLink {
    pub(super) fn new(stream: Stream) -> impl PinInit<Self> {
        pin_init!(Self {
            stream,
            send <- new_mutex!(Sending::Idle, "voidport::send"),
            send_ready <- new_condvar!("voidport::send_ready"),
        })
    }

    /// Reserves the writing of one complete frame without holding a mutex
    /// over peer I/O. Foreground waiters may leave on a signal, and cleanup
    /// leaves on source shutdown. Releasing the sender wakes both classes.
    fn sender(&self, mode: SendMode) -> Result<Sender<'_>> {
        let mut send = self.send.lock();
        while *send == Sending::Frame {
            if mode == SendMode::Cleanup {
                self.send_ready.wait(&mut send);
            } else if self.send_ready.wait_interruptible(&mut send) {
                return Err(ERESTARTSYS);
            }
        }
        if *send != Sending::Idle {
            return Err(EIO);
        }
        *send = Sending::Frame;
        Ok(Sender(self))
    }

    fn send_cleanup_frame(&self, frame: &[u8]) -> Result {
        self.stream.send_interruptibly(frame).map(|_| ())
    }
}

impl Link for StreamLink {
    fn data_room(&self, _frame_len: usize, _reply_len: usize) -> Result<Option<usize>> {
        Ok(None)
    }

    /// The data that follows a frame is part of it here. While the frame and
    /// its data are sent, only a fatal signal ends the send, and the
    /// connection with it: a long send that any signal could end partway
    /// would end the connection at every signal.
    fn transmit(
        &self,
        connection: &Connection,
        ticket: &mut Ticket,
        request: &Outbound<'_>,
        reply: Arc<Reply>,
    ) -> Transmit {
        let serialized = match self.sender(SendMode::Foreground) {
            Ok(sender) => sender,
            Err(error) => {
                connection.abandon_claim(ticket);
                return if error == ERESTARTSYS {
                    Transmit::Cancelled
                } else {
                    Transmit::Dead
                };
            }
        };
        if kernel::current!().signal_pending() {
            connection.abandon_claim(ticket);
            return Transmit::Cancelled;
        }
        {
            let mut state = connection.state.lock();
            if state.death.is_some() {
                // Connection burial has already retired this claim.
                return Transmit::Dead;
            }
            if !state.arm(ticket, reply.clone()) {
                drop(state);
                connection.bury(Death::Local("a request lost its claim before transmission"));
                reply.fail();
                return Transmit::Dead;
            }
            state.carried = true;
        }
        let written = self
            .stream
            .send_killably(request.frame)
            .and_then(|()| match request.data {
                PageData::Write(_) => request.parts(|part| send_part(&self.stream, part)),
                // The data of a read arrives in the pieces of its reply.
                PageData::None | PageData::Read(_) => Ok(()),
            });
        if let Err(error) = written {
            connection.bury(Death::Transport(error));
            return if kernel::current!().signal_pending() {
                Transmit::Cancelled
            } else {
                Transmit::Dead
            };
        }
        drop(serialized);
        Transmit::Written
    }

    fn send_callerless(
        &self,
        connection: &Connection,
        mut ticket: Ticket,
        frame: &[u8],
        reply: Arc<Reply>,
    ) -> Result {
        let _serialized = self.sender(SendMode::Cleanup).map_err(|_| EIO)?;
        {
            let mut state = connection.state.lock();
            if state.death.is_some() {
                // Connection burial has already retired this claim.
                return Err(EIO);
            }
            if !state.arm(&mut ticket, reply) {
                drop(state);
                connection.bury(Death::Local("a request lost its claim before transmission"));
                return Err(EIO);
            }
            state.carried = true;
        }
        if let Err(error) = self.send_cleanup_frame(frame) {
            connection.bury(Death::Transport(error));
        }
        // The table owns completion. The producer can send the next request
        // immediately, without retaining this reply or waiting for the peer.
        Ok(())
    }

    /// Writes the forget under the send lock, so it is recorded and written
    /// in the order of the frames on the stream.
    fn forget(
        &self,
        connection: &Connection,
        caller: Caller,
        node_id: u64,
        nlookup: u64,
    ) -> Result {
        let _serialized = self.sender(SendMode::Cleanup).map_err(|_| EIO)?;
        let mut frame = [0u8; FORGET_LEN];
        let (request_id, frame) = connection.record_forget(caller, node_id, nlookup, &mut frame)?;
        let Err(error) = self.send_cleanup_frame(frame) else {
            return Ok(());
        };
        connection.bury(Death::Transport(error));
        connection.withdraw_unsent_forget(request_id, EIO)
    }

    fn receive(&self, connection: &Connection) -> core::result::Result<Received, Death> {
        let stream = &self.stream;
        let mut header = [0u8; FRAME_HEADER_LEN];
        match read_header(stream, &mut header) {
            Ok(true) => {}
            Ok(false) => return Err(Death::Transport(crate::errno::econnreset())),
            Err(error) => return Err(death_of(error)),
        }
        let head =
            FrameHeader::parse(&header).map_err(|fault| Death::Protocol(Fault::Framing(fault)))?;
        head.validate()
            .map_err(|fault| Death::Protocol(Fault::Framing(fault)))?;
        match head.kind() {
            FrameKind::Response => {}
            // A notification is the reply to no request, so it wakes no
            // waiter and retires no id. This mount subscribes to nothing, so
            // it is read to its end and dropped, pieces included.
            FrameKind::Notification => {
                drain_message(stream, &header).map_err(death_of)?;
                return Ok(Received::Taken);
            }
            FrameKind::Request => return Err(Death::Protocol(Fault::RequestFromServer)),
        }
        let request_id = head.request_id.get();
        let raw_opcode = head.opcode.get();
        let armed = match connection.route(request_id, raw_opcode) {
            Ok(armed) => armed,
            // Cleanup completion must follow source termination, even when
            // the receiver owns the last buffer of the reply.
            Err((death, Some(armed))) => {
                let removed = Removed {
                    request_id,
                    opcode: armed.opcode,
                    reply: armed.into_reply(),
                    landing: None,
                };
                return Err(connection.lose(death, removed));
            }
            Err((death, None)) => return Err(death),
        };
        let opcode = armed.opcode;
        let reply = armed.into_reply();
        let Some(mut landing) = reply.begin_fill() else {
            // A reply that is not waiting for a message is one the death path
            // already ended, and a death is recorded once.
            return Err(Death::Local("a response lost its waiting storage"));
        };
        let removed = |landing| Removed {
            request_id,
            opcode,
            reply: reply.clone(),
            landing: Some(landing),
        };
        if let Err(death) = fill(stream, &header, &mut landing, &mut Arrival::Inline) {
            return Err(connection.lose(death, removed(landing)));
        }
        if let Err(error) = reply.validate(landing.bytes()) {
            let death = Death::Protocol(Fault::Framing(error));
            return Err(connection.lose(death, removed(landing)));
        }
        Ok(reply.end_fill(landing))
    }

    fn drain(&self, _connection: &Connection) -> Result {
        self.stream.discard_to_end()
    }

    /// The call that ends sending records the death, so it is recorded once.
    /// The death is recorded and the socket shut under the send lock, so a
    /// task that sees the death and buries the connection finds it already
    /// ended, and a clean close is never turned into an abrupt one. A clean
    /// end records the death before the end of file, so a reply the server
    /// sends after it finds every waiter already failed, and it waits for a
    /// frame in progress to end before it shuts the sending direction. The
    /// send lock is acquired before the state lock.
    fn end(&self, connection: &Connection, ending: Ending, death: Death) -> bool {
        let mut send = self.send.lock();
        *send = match (*send, ending) {
            (Sending::EndsAfterFrame | Sending::Ended, _) => return false,
            (_, Ending::Abrupt) => {
                self.stream.shutdown();
                connection.record(death);
                Sending::Ended
            }
            (Sending::Frame, Ending::Clean) => {
                connection.record(death);
                Sending::EndsAfterFrame
            }
            (Sending::Idle, Ending::Clean) => {
                connection.record(death);
                self.stream.shutdown_send();
                Sending::Ended
            }
        };
        drop(send);
        self.send_ready.notify_all();
        true
    }

    fn abort(&self) {
        self.stream.shutdown();
    }
}

/// Sends the bytes of `part` on `stream`, which no signal but a fatal one
/// ends.
fn send_part(stream: &Stream, part: &Part) -> Result {
    part.map(|bytes| {
        // SAFETY: `map` maps the `part.len()` bytes of the part for the call.
        // The mapping ends when the call returns, so `map` gives an address
        // and no slice, and the slice is made here for the call alone.
        let bytes = unsafe { core::slice::from_raw_parts(bytes, part.len()) };
        stream.send_killably(bytes)
    })
}
