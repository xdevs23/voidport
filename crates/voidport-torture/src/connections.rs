//! A worker inside a request without a reply returns only once its connection
//! ends, and the run cannot reach into the worker, so every connection a
//! worker waits on is listed here and [`Connections::end_all`] ends them.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use voidport::mount::AbortHandle;

#[derive(Debug)]
pub enum Connection {
    Kernel {
        mountpoint: PathBuf,
        abort: AbortHandle,
    },
    /// A connection to the control socket of the server, as a second
    /// descriptor of the socket the worker reads.
    Control(UnixStream),
}

impl Connection {
    fn end(&self) {
        match self {
            Self::Kernel { mountpoint, abort } => {
                if let Err(error) = abort.abort() {
                    eprintln!(
                        "!!! voidport-torture: the kernel connection of {} could not be \
                         ended, so a worker waiting on it cannot return: {error}",
                        mountpoint.display()
                    );
                }
            }
            Self::Control(stream) => {
                if let Err(error) = stream.shutdown(std::net::Shutdown::Both) {
                    eprintln!(
                        "!!! voidport-torture: a control connection could not be ended, \
                         so a worker waiting on it cannot return: {error}"
                    );
                }
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Connections {
    listed: Mutex<Listed>,
}

#[derive(Debug, Default)]
struct Listed {
    next: u64,
    ended: bool,
    open: HashMap<u64, Connection>,
}

impl Connections {
    /// A connection listed after [`Self::end_all`] is ended at once, so a worker
    /// that opens one after the run ended the others cannot wait on it.
    #[must_use]
    pub fn register(self: &Arc<Self>, connection: Connection) -> Registration {
        let mut listed = self.lock();
        if listed.ended {
            connection.end();
        }
        let id = listed.next;
        listed.next += 1;
        let _ = listed.open.insert(id, connection);
        Registration {
            connections: Arc::clone(self),
            id,
        }
    }

    pub fn end_all(&self) {
        let mut listed = self.lock();
        listed.ended = true;
        for connection in listed.open.values() {
            connection.end();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Listed> {
        self.listed
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }
}

#[derive(Debug)]
pub struct Registration {
    connections: Arc<Connections>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = self.connections.lock().open.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    #[test]
    fn ending_the_connections_frees_a_reader_and_every_later_one() {
        let connections = Arc::new(Connections::default());
        let (mut read, _peer) = UnixStream::pair().expect("a socket pair");
        let listed = connections.register(Connection::Control(
            read.try_clone().expect("a second descriptor"),
        ));
        let reader = std::thread::spawn(move || read.read(&mut [0u8; 1]));
        connections.end_all();
        assert_eq!(
            reader.join().expect("the reader returns").expect("an end"),
            0,
            "the read ends at the end of the stream"
        );
        drop(listed);
        assert!(connections.lock().open.is_empty(), "a dropped one is gone");

        let (mut late, _peer) = UnixStream::pair().expect("a socket pair");
        let _listed = connections.register(Connection::Control(
            late.try_clone().expect("a second descriptor"),
        ));
        assert_eq!(late.read(&mut [0u8; 1]).expect("an end"), 0);
    }
}
