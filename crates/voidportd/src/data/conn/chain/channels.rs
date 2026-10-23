use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::watch;
use voidport_proto::chain::{ChainHead, ChainKind, ChannelNumber};
use voidport_proto::error::FramingError;
use voidport_proto::frame::Frame;
use voidport_proto::limits::LIMITS;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::file::WriteRequest;
use zerocopy::IntoBytes as _;

use super::super::{Connection, Hello, dispatch, handshake, hello_reply, leave, read_request};
use super::reply::{Chains, Framed, Reader, answer};
use super::transfer::ChainRequest;
use crate::data::ops;
use crate::data::server::DataPlane;
use crate::data::session::Peer;
use crate::data::virtio::guest::{Areas, Chain};

pub(in crate::data) struct Channels {
    plane: Arc<DataPlane>,
    peer: Peer,
    slots: Mutex<HashMap<ChannelNumber, Slot>>,
    /// Counts the `Hello` requests being replied to, so one whose channel was
    /// ended meanwhile opens nothing.
    hellos: AtomicU64,
}

enum Slot {
    Opening(u64),
    Open {
        connection: Arc<Connection<Chains>>,
        gone: watch::Receiver<bool>,
    },
}

impl fmt::Debug for Channels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Channels")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Channels {
    pub(in crate::data) fn new(plane: Arc<DataPlane>, peer: Peer) -> Self {
        Self {
            plane,
            peer,
            slots: Mutex::default(),
            hellos: AtomicU64::new(0),
        }
    }

    pub(in crate::data) fn serve(self: &Arc<Self>, chain: Chain) {
        tokio::spawn(Arc::clone(self).serve_one(chain));
    }

    pub(in crate::data) async fn reset(&self) {
        let slots: Vec<Slot> = self.slots().drain().map(|(_, slot)| slot).collect();
        let mut leaving = Vec::new();
        for slot in slots {
            if let Slot::Open { connection, gone } = slot {
                connection.stop();
                leaving.push(gone);
            }
        }
        for gone in leaving {
            left(gone).await;
        }
    }

    async fn serve_one(self: Arc<Self>, chain: Chain) {
        let mut head = ChainHead::default();
        if chain
            .copy_out(chain.readable(), head.as_mut_bytes())
            .is_err()
        {
            return;
        }
        let channel = head.channel();
        match head.kind() {
            Ok(ChainKind::Frame) => match Framed::split(chain, head.reply_len.get()) {
                Some(framed) => self.frame(channel, Arc::new(framed)).await,
                None => self.end(channel).await,
            },
            Ok(ChainKind::Close) | Err(_) => self.end(channel).await,
            Ok(ChainKind::Reset) => self.reset().await,
        }
    }

    async fn frame(self: &Arc<Self>, channel: ChannelNumber, framed: Arc<Framed>) {
        let open = match self.slots().get(&channel) {
            None => None,
            Some(Slot::Opening(_)) => return,
            Some(Slot::Open { connection, .. }) => Some(Arc::clone(connection)),
        };
        match open {
            None => self.open(channel, framed).await,
            Some(connection) => self.request(channel, connection, framed).await,
        }
    }

    async fn open(self: &Arc<Self>, channel: ChannelNumber, framed: Arc<Framed>) {
        let hello = self.hellos.fetch_add(1, Ordering::Relaxed);
        {
            let mut slots = self.slots();
            if slots.contains_key(&channel) {
                return;
            }
            slots.insert(channel, Slot::Opening(hello));
        }
        let mut reader = Reader::new(&framed.chain);
        let judged = handshake(&mut reader, &self.plane, &self.peer).await;
        let whole = reader.is_done();
        let (request_id, session, link) = match judged {
            Ok(Hello::Accepted {
                request_id,
                session,
                link,
            }) if whole => (request_id, session, link),
            Ok(Hello::Accepted { session, link, .. }) => {
                self.abandon(channel, hello);
                return leave(&self.plane, &session, &link);
            }
            Ok(Hello::Refused { request_id, errno }) => {
                self.abandon(channel, hello);
                if let Ok(reply) = ops::error_reply(request_id, Opcode::Hello, errno) {
                    drop(answer(&framed, &reply).await);
                }
                return;
            }
            Ok(Hello::Closed) | Err(_) => return self.abandon(channel, hello),
        };
        let Ok(reply) = hello_reply(request_id, link.id(), session.token()) else {
            self.abandon(channel, hello);
            return leave(&self.plane, &session, &link);
        };
        let connection = Connection::new(&self.plane, &session, &link, Chains::default());
        let (gone_sender, gone) = watch::channel(false);
        let opened = {
            let mut slots = self.slots();
            let slot = slots.get_mut(&channel);
            match slot {
                Some(slot) if matches!(*slot, Slot::Opening(replying) if replying == hello) => {
                    *slot = Slot::Open {
                        connection: Arc::clone(&connection),
                        gone,
                    };
                    true
                }
                _ => false,
            }
        };
        if !opened {
            return leave(&self.plane, &session, &link);
        }
        tokio::spawn(Arc::clone(self).watch(channel, Arc::clone(&connection), gone_sender));
        if answer(&framed, &reply).await.is_err() {
            connection.stop();
        }
    }

    fn abandon(&self, channel: ChannelNumber, hello: u64) {
        let mut slots = self.slots();
        if matches!(slots.get(&channel), Some(Slot::Opening(replying)) if *replying == hello) {
            slots.remove(&channel);
        }
    }

    /// The task is started while the channel still belongs to the connection,
    /// under the lock that the end of the connection takes to free the channel:
    /// a connection that has begun waiting for its tasks never starts another.
    async fn request(
        &self,
        channel: ChannelNumber,
        connection: Arc<Connection<Chains>>,
        framed: Arc<Framed>,
    ) {
        let (bytes, payload) = {
            let mut reader = Reader::new(&framed.chain);
            match read_request(&mut reader).await {
                Ok(Some(bytes)) => (bytes, framed.chain.readable().starting_at(reader.at)),
                Ok(None) => return connection.stop(),
                Err(error) => {
                    tracing::debug!(%error, "closing a channel on a chain it cannot read");
                    return connection.stop();
                }
            }
        };
        let slots = self.slots();
        if matches!(slots.get(&channel), Some(Slot::Open { connection: open, .. }) if Arc::ptr_eq(open, &connection))
        {
            connection.spawn(serve_request(
                Arc::clone(&connection),
                framed,
                bytes,
                payload,
            ));
        }
    }

    async fn end(&self, channel: ChannelNumber) {
        let open = match self.slots().get(&channel) {
            Some(Slot::Open { connection, gone }) => Some((Arc::clone(connection), gone.clone())),
            _ => None,
        };
        if let Some((connection, gone)) = open {
            connection.stop();
            left(gone).await;
        }
    }

    async fn watch(
        self: Arc<Self>,
        channel: ChannelNumber,
        connection: Arc<Connection<Chains>>,
        gone: watch::Sender<bool>,
    ) {
        let mut stopped = connection.stopped();
        drop(stopped.wait_for(|stopped| *stopped).await);
        {
            let mut slots = self.slots();
            if matches!(slots.get(&channel), Some(Slot::Open { connection: open, .. }) if Arc::ptr_eq(open, &connection))
            {
                slots.remove(&channel);
            }
        }
        connection.close().await;
        leave(&self.plane, &connection.session, &connection.link);
        gone.send_modify(|gone| *gone = true);
    }

    fn slots(&self) -> MutexGuard<'_, HashMap<ChannelNumber, Slot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

async fn left(mut gone: watch::Receiver<bool>) {
    drop(gone.wait_for(|gone| *gone).await);
}

async fn serve_request(
    connection: Arc<Connection<Chains>>,
    framed: Arc<Framed>,
    bytes: Vec<u8>,
    payload: Areas,
) {
    let (request_id, opcode) = match fitting(&bytes, &payload) {
        Ok(fitting) => fitting,
        Err(error) => return connection.poison(&error),
    };
    // A request without a reply, a `forget`, may share its id with a later
    // request.
    let _registered = if opcode.has_response() {
        let Some(registered) = connection.replies.register(request_id, &framed) else {
            return connection.poison(&FramingError::DuplicateRequestId { request_id });
        };
        Some(registered)
    } else {
        None
    };
    let request = ChainRequest { framed, payload };
    match dispatch(&connection, request, bytes).await {
        Ok(true) => {}
        Ok(false) => connection.stop(),
        Err(error) => {
            tracing::debug!(%error, "closing a channel on a request it could not handle");
            connection.stop();
        }
    }
}

fn fitting(bytes: &[u8], payload: &Areas) -> Result<(u64, Opcode), FramingError> {
    let frame = Frame::parse(bytes, &LIMITS)?;
    let opcode = frame
        .opcode()
        .map_err(|unknown| FramingError::UnknownOpcode { opcode: unknown.0 })?;
    let declared = match opcode {
        Opcode::Write => frame.request::<WriteRequest>()?.body().data_len.get(),
        _ => 0,
    };
    if u32::try_from(payload.len()) != Ok(declared) {
        return Err(FramingError::PayloadLengthMismatch {
            declared,
            found: payload.len(),
        });
    }
    Ok((frame.request_id(), opcode))
}
