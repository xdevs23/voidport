//! The control-plane listener: framing and connection lifecycle.
//!
//! The protocol is newline-delimited JSON — one request object per line, one
//! response object per line, in order per connection. A connection is handled
//! strictly sequentially: the control plane is low-frequency operator traffic,
//! and in-order replies make the transcript readable by a human with `nc`.
//!
//! Two rules keep a client from hurting the server:
//!
//! * **Request lines are bounded** ([`MAX_REQUEST_LINE`]). The bound is
//!   enforced *while reading*, not after, so an endless line cannot exhaust
//!   memory; it is answered with a structured error and the connection then
//!   closes, because the rest of that line cannot be interpreted.
//! * **Malformed JSON and unknown operations are not fatal.** They get a
//!   structured error and the connection lives on — that is what lets a newer
//!   CLI talk to an older server and be told so.
//!
//! Every line read is answered, empty lines included: an empty line is not
//! valid JSON, so it is malformed input like any other. Silently skipping it
//! would break the one-request/one-response rule the whole protocol rests on —
//! a client that pipelines would start matching answers to the wrong requests.
//!
//! Request handling itself runs on the blocking pool: a mutation fsyncs the
//! state file, and blocking a reactor thread for a disk write is exactly the
//! bug that makes an async server stall.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use voidport_control::{ControlError, ErrorCode, Response};

use super::service::Service;
use super::socket::ControlSocket;

/// The largest request line the server will read, in bytes.
pub const MAX_REQUEST_LINE: usize = 1024 * 1024;

/// Serves the control plane until `shutdown` resolves.
///
/// On shutdown the sequence is deliberate: stop accepting, tell every
/// connection to stop — between requests, or in the middle of writing an
/// answer the client is not reading — wait for all of them to finish, and only
/// then unlink the socket (which happens as `socket` is dropped) and release
/// the state file to whatever starts next.
///
/// Connections are asked to stop, not aborted, because aborting one
/// mid-request would not stop the request: the handler runs on the blocking
/// pool, and dropping its join handle merely detaches it. A detached handler
/// can still take the mutation lock, persist, and publish — after the server
/// has unlinked the socket and dropped the single-instance lock, where a
/// freshly started daemon owning the same state file would race it. Joining
/// the connections is what makes "shutdown completes any in-flight mutation"
/// structurally true instead of a hope.
///
/// # Errors
///
/// Returns an error only if the bound socket cannot be handed to the async
/// reactor.
pub async fn serve(
    mut socket: ControlSocket,
    service: Arc<Service>,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    let listener = socket
        .take()
        .ok_or_else(|| io::Error::other("the control socket was already served"))?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    let mut connections = JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);
    let (stop, stop_signal) = watch::channel(false);

    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    connections.spawn(serve_connection(
                        stream,
                        Arc::clone(&service),
                        stop_signal.clone(),
                    ));
                }
                Err(error) => {
                    tracing::warn!(%error, "control connection could not be accepted");
                }
            },
            // Reap finished connections so the set does not grow without
            // bound on a long-lived server.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }

    let _ = stop.send(true);
    while connections.join_next().await.is_some() {}
    drop(socket);
    Ok(())
}

/// Serves one connection to completion, logging why it ended.
async fn serve_connection(stream: UnixStream, service: Arc<Service>, stop: watch::Receiver<bool>) {
    if let Err(error) = converse(stream, service, stop).await {
        tracing::debug!(%error, "control connection ended");
    }
}

/// The request/response loop of one connection.
async fn converse(
    stream: UnixStream,
    service: Arc<Service>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    loop {
        line.clear();
        let mut bounded = (&mut reader).take(bound());
        let read = tokio::select! {
            // Shutdown outranks a line that is ready to read, so a client that
            // keeps talking cannot hold the server open.
            biased;
            // A request already being handled runs to completion, because its
            // handler cannot be cancelled once it is on the blocking pool.
            // Shutdown is therefore observed here, between requests, and again
            // while the answer is written — the only other step whose duration
            // the client, not the server, decides.
            _ = stop.wait_for(|stop| *stop) => return Ok(()),
            read = bounded.read_until(b'\n', &mut line) => read?,
        };
        if read == 0 {
            return Ok(());
        }
        let request = trim_line_ending(&line);
        if request.len() > MAX_REQUEST_LINE {
            let error = ControlError::new(
                ErrorCode::RequestTooLarge,
                format!("a request line must be at most {MAX_REQUEST_LINE} bytes"),
            );
            respond(&mut writer, &Response::error(error), &mut stop).await?;
            return Ok(());
        }

        // An empty line is answered too: it is malformed JSON, and one line in
        // must always mean one line out.
        let request = request.to_vec();
        let handler = Arc::clone(&service);
        let response = tokio::task::spawn_blocking(move || handler.handle_line(&request))
            .await
            .map_err(io::Error::other)?;
        if respond(&mut writer, &response, &mut stop).await? == Delivery::Abandoned {
            return Ok(());
        }
    }
}

/// How many bytes one line may consume: content, CRLF, and one proof byte.
fn bound() -> u64 {
    MAX_REQUEST_LINE as u64 + 3
}

/// Strips the line ending, tolerating `\r\n` for the benefit of hand-typed
/// input.
fn trim_line_ending(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// What became of a response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    /// The client has the whole line.
    Sent,
    /// Shutdown started while the client was refusing to read it.
    Abandoned,
}

/// Writes one response line and flushes it, so a client that waits for its
/// answer is never left waiting on a buffer.
///
/// The write is abandoned if shutdown starts first. A client that stops
/// reading its answers fills the socket buffer and wedges this write forever,
/// and shutdown waits for every connection — so without this, one such client
/// (a `voidport-ctl` killed mid-command, say) would hold the whole server open,
/// with the socket unlinked and the state file locked, past SIGTERM.
async fn respond<W>(
    writer: &mut W,
    response: &Response,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<Delivery>
where
    W: AsyncWriteExt + Unpin,
{
    let mut line = serde_json::to_vec(response).map_err(io::Error::other)?;
    line.push(b'\n');
    let written = async {
        writer.write_all(&line).await?;
        writer.flush().await
    };
    tokio::select! {
        biased;
        _ = stop.wait_for(|stop| *stop) => Ok(Delivery::Abandoned),
        written = written => written.map(|()| Delivery::Sent),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_endings_are_trimmed_but_content_is_not() {
        assert_eq!(trim_line_ending(b"{}\n"), b"{}");
        assert_eq!(trim_line_ending(b"{}\r\n"), b"{}");
        assert_eq!(trim_line_ending(b"{}"), b"{}");
        assert_eq!(trim_line_ending(b"\n"), b"");
        assert_eq!(trim_line_ending(b" {} "), b" {} ");
    }

    #[test]
    fn the_read_bound_admits_maximal_content_crlf_and_one_proof_byte() {
        assert_eq!(bound(), MAX_REQUEST_LINE as u64 + 3);
    }
}
