use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, ReadBuf};
use voidport_proto::chain::CHAIN_HEAD_LEN;

use super::super::Replies;
use crate::data::virtio::guest::{Areas, Chain};
use crate::data::wire::Out;

pub(super) struct Framed {
    pub(super) chain: Chain,
    reply: Areas,
    pub(super) data: Areas,
}

impl Framed {
    pub(super) fn split(chain: Chain, reply_len: u32) -> Option<Self> {
        let reply_len = usize::try_from(reply_len).ok()?;
        if !chain.accessible() || reply_len > chain.writable().len() {
            return None;
        }
        Some(Self {
            reply: chain.writable().slice(0, reply_len),
            data: chain.writable().starting_at(reply_len),
            chain,
        })
    }
}

#[derive(Default)]
pub(super) struct Chains(Mutex<HashMap<u64, Arc<Framed>>>);

impl Chains {
    pub(super) fn register(&self, request_id: u64, framed: &Arc<Framed>) -> Option<Registered<'_>> {
        match self.lock().entry(request_id) {
            Entry::Occupied(_) => return None,
            Entry::Vacant(vacant) => {
                vacant.insert(Arc::clone(framed));
            }
        }
        Some(Registered {
            chains: self,
            request_id,
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<u64, Arc<Framed>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Replies for Chains {
    // Share notifications have no chain to travel in.
    const NOTIFIES: bool = false;

    type Reply<'a> = Answer;

    async fn reply(&self, request_id: u64) -> Option<Answer> {
        let framed = self.lock().get(&request_id).map(Arc::clone);
        framed.map(Answer::new)
    }
}

pub(super) struct Registered<'c> {
    chains: &'c Chains,
    request_id: u64,
}

impl Drop for Registered<'_> {
    fn drop(&mut self) {
        drop(self.chains.lock().remove(&self.request_id));
    }
}

pub(super) struct Answer {
    framed: Arc<Framed>,
    at: usize,
}

impl Answer {
    fn new(framed: Arc<Framed>) -> Self {
        Self { framed, at: 0 }
    }
}

impl Out for Answer {
    async fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.framed
            .chain
            .copy_in(&self.framed.reply.starting_at(self.at), bytes)
            .map_err(io::Error::other)?;
        self.at += bytes.len();
        Ok(())
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.framed.chain.keep();
        Ok(())
    }
}

pub(super) async fn answer(framed: &Arc<Framed>, reply: &[u8]) -> io::Result<()> {
    let mut answer = Answer::new(Arc::clone(framed));
    answer.put(reply).await?;
    answer.flush().await
}

pub(super) struct Reader<'c> {
    chain: &'c Chain,
    pub(super) at: usize,
}

impl<'c> Reader<'c> {
    pub(super) fn new(chain: &'c Chain) -> Self {
        Self {
            chain,
            at: CHAIN_HEAD_LEN,
        }
    }

    pub(super) fn is_done(&self) -> bool {
        self.at == self.chain.readable().len()
    }
}

impl AsyncRead for Reader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let reader = self.get_mut();
        let readable = reader.chain.readable();
        let len = buffer
            .remaining()
            .min(readable.len().saturating_sub(reader.at));
        let into = buffer.initialize_unfilled_to(len);
        if let Err(unreached) = reader
            .chain
            .copy_out(&readable.starting_at(reader.at), into)
        {
            return Poll::Ready(Err(io::Error::other(unreached)));
        }
        buffer.advance(len);
        reader.at += len;
        Poll::Ready(Ok(()))
    }
}
