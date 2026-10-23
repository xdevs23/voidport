use std::sync::Arc;

use voidport_proto::frame::Frame;
use voidport_proto::limits::LIMITS;
use voidport_proto::opcode::Opcode;
use voidport_proto::ops::recall::{RenewRequest, RenewResponse};
use voidport_session::Window;
use zerocopy::byteorder::little_endian::U64;

use super::super::ops;
use super::super::wire::Threads as _;
use super::{Connection, Replies};
use crate::host::lease;

/// A break time that leaves no window, or that cannot be read, gets a window of
/// zero, and the leases of the session are recalled and given up, since nothing
/// bounds the pages the guest caches under them any more.
pub(super) async fn renew<P: Replies>(connection: Arc<Connection<P>>, bytes: Vec<u8>) {
    let Ok(frame) = Frame::parse(&bytes, &LIMITS) else {
        return connection.stop();
    };
    let request_id = frame.request_id();
    if let Err(error) = frame.request::<RenewRequest>() {
        return connection.poison(&error);
    }
    let Ok(mut thread) = connection.thread().await else {
        return;
    };
    let break_time = thread.run(lease::break_time).await;
    drop(thread);
    let window = match break_time {
        Ok(Ok(break_time)) => Window::of(break_time),
        Ok(Err(error)) => {
            tracing::warn!(%error, "the lease break time cannot be read, so a guest is granted no window");
            None
        }
        Err(_) => None,
    };
    let granted = if let Some(window) = window {
        let mut stopped = connection.stopped();
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => return,
            granted = connection.session.recalls().renew(window) => granted,
        }
    } else {
        connection.session.release_leases();
        None
    };
    let (window_ns, period_ns) = Window::to_nanos(granted);
    let granted = RenewResponse {
        window_ns: U64::new(window_ns),
        period_ns: U64::new(period_ns),
    };
    match ops::encode_outcome(request_id, Opcode::Renew, Ok(granted)) {
        Ok(reply) => connection.answer(request_id, &reply).await,
        Err(error) => connection.poison(&error),
    }
}
