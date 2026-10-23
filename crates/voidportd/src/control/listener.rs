use std::io;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::watch;
use tokio::task::JoinSet;
use voidport_control::{ControlError, ErrorCode, Response};

use super::service::Service;
use super::socket::ControlSocket;

pub const MAX_REQUEST_LINE: usize = 1024 * 1024;

/// Connections are asked to stop, not aborted: a handler on the blocking pool
/// still runs when its join handle is dropped, and could persist after the
/// socket is unlinked and the state file lock is released.
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
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }

    let _ = stop.send(true);
    while connections.join_next().await.is_some() {}
    drop(socket);
    Ok(())
}

async fn serve_connection(stream: UnixStream, service: Arc<Service>, stop: watch::Receiver<bool>) {
    if let Err(error) = converse(stream, service, stop).await {
        tracing::debug!(%error, "control connection ended");
    }
}

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
            // Shutdown outranks a ready line, so a client that sends without
            // pause cannot hold the server open.
            biased;
            // A handler on the blocking pool cannot be cancelled, so shutdown is
            // observed between requests and when writing an answer would wait.
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

        // An empty line is malformed JSON and is answered like any other line.
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

fn trim_line_ending(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    Sent,
    /// Shutdown had started and the next write would have had to wait. The
    /// client may hold a line without its newline.
    Abandoned,
}

/// Every request gets an answer, so the write comes before shutdown.
/// After shutdown is signalled the line goes on only while the socket takes
/// bytes without making the server wait. Otherwise a client that stopped
/// reading would hold shutdown open past SIGTERM. An abandoned line lacks its
/// newline and is no answer.
async fn respond(
    writer: &mut OwnedWriteHalf,
    response: &Response,
    stop: &mut watch::Receiver<bool>,
) -> io::Result<Delivery> {
    enum Step {
        Wrote(usize),
        Stopped,
    }

    let mut line = serde_json::to_vec(response).map_err(io::Error::other)?;
    line.push(b'\n');
    let mut rest = line.as_slice();
    while !rest.is_empty() {
        let step = tokio::select! {
            // The write is polled first, so a pending answer goes out.
            biased;
            wrote = writer.write(rest) => Step::Wrote(wrote?),
            _ = stop.wait_for(|stop| *stop) => Step::Stopped,
        };
        match step {
            Step::Wrote(0) => return Err(io::ErrorKind::WriteZero.into()),
            Step::Wrote(wrote) => rest = &rest[wrote..],
            Step::Stopped => return write_without_waiting(writer, rest),
        }
    }
    // A unix stream buffers nothing, so there is nothing to flush.
    Ok(Delivery::Sent)
}

/// Asks the socket itself with a send that never waits: the reactor reports a
/// fresh socket as not ready until its first event, which would lose the answer
/// to a client that is reading.
fn write_without_waiting(writer: &OwnedWriteHalf, mut rest: &[u8]) -> io::Result<Delivery> {
    use rustix::net::{SendFlags, send};

    let socket: &UnixStream = writer.as_ref();
    while !rest.is_empty() {
        match send(socket, rest, SendFlags::DONTWAIT | SendFlags::NOSIGNAL) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(sent) => rest = &rest[sent..],
            Err(rustix::io::Errno::INTR) => {}
            Err(rustix::io::Errno::AGAIN) => return Ok(Delivery::Abandoned),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Delivery::Sent)
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

    fn response_of(size: usize) -> Response {
        Response::error(ControlError::new(
            ErrorCode::RequestTooLarge,
            "x".repeat(size),
        ))
    }

    async fn deliver(
        writer: &mut tokio::net::unix::OwnedWriteHalf,
        response: &Response,
        stop: &mut watch::Receiver<bool>,
    ) -> Delivery {
        respond(writer, response, stop)
            .await
            .expect("the socket is open")
    }

    #[tokio::test]
    async fn an_owed_answer_is_written_whole_after_shutdown_is_signalled() {
        let (server, client) = UnixStream::pair().expect("a socket pair");
        let (_reader, mut writer) = server.into_split();
        let (stop, mut stopped) = watch::channel(false);
        stop.send(true).expect("a receiver exists");

        let response = response_of(64);
        assert_eq!(
            deliver(&mut writer, &response, &mut stopped).await,
            Delivery::Sent
        );
        drop(writer);
        let mut received = Vec::new();
        BufReader::new(client)
            .read_to_end(&mut received)
            .await
            .expect("readable");
        let mut expected = serde_json::to_vec(&response).expect("encodes");
        expected.push(b'\n');
        assert_eq!(received, expected);
    }

    #[tokio::test]
    async fn a_peer_that_does_not_read_gets_an_abandoned_answer_without_its_newline() {
        let (server, client) = UnixStream::pair().expect("a socket pair");
        let (_reader, mut writer) = server.into_split();
        let (stop, mut stopped) = watch::channel(false);
        stop.send(true).expect("a receiver exists");

        let response = response_of(16 * 1024 * 1024);
        assert_eq!(
            deliver(&mut writer, &response, &mut stopped).await,
            Delivery::Abandoned
        );
        drop(writer);
        let mut received = Vec::new();
        BufReader::new(client)
            .read_to_end(&mut received)
            .await
            .expect("readable");
        let line = serde_json::to_vec(&response).expect("encodes");
        assert!(
            line.starts_with(&received),
            "what arrived is part of the answer"
        );
        assert!(received.len() < line.len());
        assert!(!received.contains(&b'\n'), "and it never ends as an answer");
    }

    #[tokio::test]
    async fn a_write_waiting_for_a_peer_that_does_not_read_ends_at_shutdown() {
        let (server, _client) = UnixStream::pair().expect("a socket pair");
        let (_reader, mut writer) = server.into_split();
        let (stop, mut stopped) = watch::channel(false);

        let response = response_of(16 * 1024 * 1024);
        let mut delivery = std::pin::pin!(deliver(&mut writer, &response, &mut stopped));
        let waiting = std::future::poll_fn(|cx| {
            std::task::Poll::Ready(delivery.as_mut().poll(cx).is_pending())
        })
        .await;
        assert!(waiting, "the write waits for the peer");
        stop.send(true).expect("a receiver exists");
        assert_eq!(delivery.await, Delivery::Abandoned);
    }

    #[test]
    fn the_read_bound_admits_maximal_content_crlf_and_one_proof_byte() {
        assert_eq!(bound(), MAX_REQUEST_LINE as u64 + 3);
    }
}
