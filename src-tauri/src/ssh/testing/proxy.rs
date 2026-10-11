//! A TCP proxy in front of a scratch sshd that can go silent (bytes held, sockets open: a dead Wi-Fi link) or cut the connections.
//! Keepalive, a connection dropped mid-command, a handshake that never answers and an abandoned login all need a link that misbehaves
//! on demand. Ported from the spike's `proxy.rs`; the proxy owns a small tokio runtime, so tests stay synchronous.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Bytes flow both ways.
    Forward,
    /// Bytes are read and held, nothing is delivered, the sockets stay open.
    Blackhole,
    /// Every connection is closed now, and new ones are closed on arrival.
    Cut,
}

#[derive(Default)]
struct Stats {
    open: AtomicUsize,
    accepted: AtomicUsize,
}

/// Counts a client connection as open for as long as it lives.
struct OpenGuard(Arc<Stats>);

impl OpenGuard {
    fn new(stats: &Arc<Stats>) -> OpenGuard {
        stats.accepted.fetch_add(1, Ordering::SeqCst);
        stats.open.fetch_add(1, Ordering::SeqCst);
        OpenGuard(Arc::clone(stats))
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Proxy {
    /// Where clients connect (127.0.0.1).
    pub port: u16,
    mode: watch::Sender<Mode>,
    stats: Arc<Stats>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Proxy {
    pub fn start(target_port: u16) -> Proxy {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().expect("the proxy's runtime");
        let listener = runtime.block_on(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))).expect("bind the proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let (mode, watcher) = watch::channel(Mode::Forward);
        let stats = Arc::new(Stats::default());
        let counted = Arc::clone(&stats);
        runtime.spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let (watcher, stats) = (watcher.clone(), Arc::clone(&counted));
                tokio::spawn(async move {
                    let _open = OpenGuard::new(&stats);
                    if *watcher.borrow() == Mode::Cut {
                        return;
                    }
                    let Ok(server) = TcpStream::connect((Ipv4Addr::LOCALHOST, target_port)).await else { return };
                    let (client_read, client_write) = client.into_split();
                    let (server_read, server_write) = server.into_split();
                    let up = tokio::spawn(pipe(client_read, server_write, watcher.clone()));
                    let down = tokio::spawn(pipe(server_read, client_write, watcher));
                    let _ = tokio::join!(up, down);
                });
            }
        });
        Proxy { port, mode, stats, runtime: Some(runtime) }
    }

    pub fn set(&self, mode: Mode) {
        self.mode.send_replace(mode);
    }

    /// Client connections that are open right now (accepted and not yet finished).
    pub fn open_connections(&self) -> usize {
        self.stats.open.load(Ordering::SeqCst)
    }

    /// Client connections accepted so far, including the ones that were cut on arrival.
    pub fn accepted(&self) -> usize {
        self.stats.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

async fn pipe(mut from: OwnedReadHalf, mut to: OwnedWriteHalf, mut mode: watch::Receiver<Mode>) {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let read = tokio::select! {
            read = from.read(&mut buffer) => read,
            _ = mode.wait_for(|mode| *mode == Mode::Cut) => break,
        };
        let count = match read {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        // Black hole: hold what was read until the link comes back (or is cut).
        loop {
            let current = *mode.borrow();
            match current {
                Mode::Forward => break,
                Mode::Cut => return,
                Mode::Blackhole => {}
            }
            if mode.changed().await.is_err() {
                return;
            }
        }
        if to.write_all(&buffer[..count]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::{Duration, Instant};

    use super::{Mode, Proxy};

    /// A server that sends back every byte it receives. Returns its port.
    fn echo_server() -> u16 {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok((mut socket, _)) = listener.accept() {
                std::thread::spawn(move || {
                    let mut buffer = [0u8; 1024];
                    while let Ok(count) = socket.read(&mut buffer) {
                        if count == 0 || socket.write_all(&buffer[..count]).is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    fn connect(port: u16) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        // Bounded: if forwarding broke, the test must fail at a read instead of hanging the suite.
        stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        stream
    }

    fn round_trip(client: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
        client.write_all(bytes).unwrap();
        let mut reply = vec![0u8; bytes.len()];
        client.read_exact(&mut reply).unwrap();
        reply
    }

    fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("timed out waiting for: {what}");
    }

    #[test]
    fn forward_passes_bytes_both_ways() {
        let proxy = Proxy::start(echo_server());
        let mut client = connect(proxy.port);
        assert_eq!(round_trip(&mut client, b"hello"), b"hello");
    }

    #[test]
    fn blackhole_holds_the_bytes_until_forward_releases_them() {
        let proxy = Proxy::start(echo_server());
        let mut client = connect(proxy.port);
        assert_eq!(round_trip(&mut client, b"warm"), b"warm");

        proxy.set(Mode::Blackhole);
        client.write_all(b"held").unwrap();
        client.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut reply = [0u8; 4];
        assert!(client.read_exact(&mut reply).is_err(), "nothing may arrive through a black hole");

        proxy.set(Mode::Forward);
        client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        client.read_exact(&mut reply).expect("released in time");
        assert_eq!(&reply, b"held");
    }

    #[test]
    fn cut_closes_open_connections_and_new_ones() {
        let proxy = Proxy::start(echo_server());
        let mut client = connect(proxy.port);
        assert_eq!(round_trip(&mut client, b"warm"), b"warm");

        proxy.set(Mode::Cut);
        let mut byte = [0u8; 1];
        let read = client.read(&mut byte);
        assert!(matches!(read, Ok(0) | Err(_)), "an open connection must end after a cut, got {read:?}");

        let mut late = connect(proxy.port);
        let read = late.read(&mut byte);
        assert!(matches!(read, Ok(0) | Err(_)), "a new connection must be closed on arrival, got {read:?}");
    }

    #[test]
    fn it_counts_the_connections_that_are_open_and_the_ones_it_accepted() {
        let proxy = Proxy::start(echo_server());
        assert_eq!((proxy.open_connections(), proxy.accepted()), (0, 0));
        let mut first = connect(proxy.port);
        let mut second = connect(proxy.port);
        assert_eq!(round_trip(&mut first, b"a"), b"a");
        assert_eq!(round_trip(&mut second, b"b"), b"b");
        assert_eq!((proxy.open_connections(), proxy.accepted()), (2, 2));
        drop(first);
        eventually("the first connection to be counted as closed", || proxy.open_connections() == 1);
        drop(second);
        eventually("the second connection to be counted as closed", || proxy.open_connections() == 0);
        assert_eq!(proxy.accepted(), 2, "closing does not undo the count of accepted connections");
    }
}
