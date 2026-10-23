//! The vhost-user messages are read on a thread of their own, since the library
//! that reads them blocks. The connection ends at the first message that fails,
//! and its end stops every queue and ends every channel of the device.

mod device;
pub(in crate::data) mod guest;
mod ring;

use std::sync::{Arc, Mutex, PoisonError};

use tokio::runtime::Handle;
use vhost::vhost_user::BackendReqHandler;
use voidport_vhost::backend::Handler;

use self::device::Device;
use super::conn::Channels;
use super::server::DataPlane;
use super::session::Peer;

pub(super) fn serve(stream: tokio::net::UnixStream, plane: Arc<DataPlane>, peer: Peer) {
    let stream = match stream.into_std().and_then(|stream| {
        stream.set_nonblocking(false)?;
        Ok(stream)
    }) {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(%error, "a vhost-user connection could not be handled");
            return;
        }
    };
    let runtime = Handle::current();
    let channels = Arc::new(Channels::new(plane, peer));
    let spawned = std::thread::Builder::new()
        .name("voidport-vhost-user".to_owned())
        .spawn(move || converse(stream, &channels, &runtime));
    if let Err(error) = spawned {
        tracing::warn!(%error, "a vhost-user connection could not be handled");
    }
}

fn converse(stream: std::os::unix::net::UnixStream, channels: &Arc<Channels>, runtime: &Handle) {
    let device = Arc::new(Mutex::new(Handler::new(Device::new(
        Arc::clone(channels),
        runtime.clone(),
    ))));
    let mut handler = BackendReqHandler::from_stream(stream, Arc::clone(&device));
    let ended = loop {
        if let Err(error) = handler.handle_request() {
            break error;
        }
    };
    tracing::debug!(error = %ended, "a vhost-user connection ended");
    device
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .backend()
        .stop();
    let channels = Arc::clone(channels);
    drop(runtime.spawn(async move { channels.reset().await }));
}
