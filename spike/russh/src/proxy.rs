//! A TCP proxy in front of a scratch sshd that can go silent (bytes held, sockets open: a dead Wi-Fi link) or cut the connections.
//! Keepalive, a connection dropped mid-command and a handshake that never answers all need a link that misbehaves on demand.

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Bytes flow both ways.
    Forward,
    /// Bytes are read and held, nothing is delivered, the sockets stay open.
    Blackhole,
    /// Every connection is closed now, and new ones are closed on arrival.
    Cut,
}

pub struct Proxy {
    /// Where clients connect (127.0.0.1).
    pub port: u16,
    mode: watch::Sender<Mode>,
    accept_loop: JoinHandle<()>,
}

impl Proxy {
    pub async fn start(target_port: u16) -> Proxy {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind the proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let (mode, watcher) = watch::channel(Mode::Forward);
        let accept_loop = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let watcher = watcher.clone();
                tokio::spawn(async move {
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
        Proxy { port, mode, accept_loop }
    }

    pub fn set(&self, mode: Mode) {
        self.mode.send_replace(mode);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.accept_loop.abort();
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
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{Mode, Proxy};

    /// A server that sends back every byte it receives. Returns its port.
    async fn echo_server() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    while let Ok(count) = socket.read(&mut buffer).await {
                        if count == 0 || socket.write_all(&buffer[..count]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    async fn round_trip(client: &mut TcpStream, bytes: &[u8]) -> Vec<u8> {
        client.write_all(bytes).await.unwrap();
        let mut reply = vec![0u8; bytes.len()];
        // Bounded: if forwarding broke, the test must fail here instead of hanging `cargo test --lib`.
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut reply)).await.expect("echo in time").unwrap();
        reply
    }

    #[tokio::test]
    async fn forward_passes_bytes_both_ways() {
        let proxy = Proxy::start(echo_server().await).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        assert_eq!(round_trip(&mut client, b"hello").await, b"hello");
    }

    #[tokio::test]
    async fn blackhole_holds_the_bytes_until_forward_releases_them() {
        let proxy = Proxy::start(echo_server().await).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        assert_eq!(round_trip(&mut client, b"warm").await, b"warm");

        proxy.set(Mode::Blackhole);
        client.write_all(b"held").await.unwrap();
        let mut reply = [0u8; 4];
        let silent = tokio::time::timeout(Duration::from_millis(500), client.read_exact(&mut reply)).await;
        assert!(silent.is_err(), "nothing may arrive through a black hole");

        proxy.set(Mode::Forward);
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut reply)).await.expect("released in time").unwrap();
        assert_eq!(&reply, b"held");
    }

    #[tokio::test]
    async fn cut_closes_open_connections_and_new_ones() {
        let proxy = Proxy::start(echo_server().await).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        assert_eq!(round_trip(&mut client, b"warm").await, b"warm");

        proxy.set(Mode::Cut);
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(3), client.read(&mut byte)).await.expect("closed in time");
        assert!(matches!(read, Ok(0) | Err(_)), "an open connection must end after a cut, got {read:?}");

        let mut late = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let read = tokio::time::timeout(Duration::from_secs(3), late.read(&mut byte)).await.expect("closed in time");
        assert!(matches!(read, Ok(0) | Err(_)), "a new connection must be closed on arrival, got {read:?}");
    }
}
