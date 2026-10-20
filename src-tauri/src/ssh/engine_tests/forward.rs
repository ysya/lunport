use super::{engine, open_session, open_session_to};
use crate::ssh::{
    forward::{ForwardKind, ForwardSpec},
    testing::{doubles::VaultAuth, eventually, fixture::Server, harness::tools},
    Target,
};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

struct Echo {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Echo {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut workers = vec![];
            while !flag.load(Ordering::Acquire) {
                if let Ok((mut socket, _)) = listener.accept() {
                    let stop = Arc::clone(&flag);
                    workers.push(std::thread::spawn(move || {
                        socket
                            .set_read_timeout(Some(Duration::from_millis(100)))
                            .unwrap();
                        socket
                            .set_write_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        let mut buffer = [0; 8192];
                        while !stop.load(Ordering::Acquire) {
                            match socket.read(&mut buffer) {
                                Ok(0) => {
                                    let _ = socket.shutdown(Shutdown::Write);
                                    break;
                                }
                                Ok(n) => {
                                    if socket.write_all(&buffer[..n]).is_err() {
                                        break;
                                    }
                                }
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) => {}
                                Err(_) => break,
                            }
                        }
                    }));
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            port,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn spec(kind: ForwardKind, target: u16) -> ForwardSpec {
    ForwardSpec {
        kind,
        bind_address: "127.0.0.1".into(),
        port: 0,
        target_host: if kind == ForwardKind::Dynamic {
            "".into()
        } else {
            "127.0.0.1".into()
        },
        target_port: if kind == ForwardKind::Dynamic {
            0
        } else {
            target
        },
    }
}
fn socket(port: u16) -> TcpStream {
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}
fn round_trip(mut socket: TcpStream) {
    let payload: Vec<u8> = (0..16384).map(|i| (i % 251) as u8).collect();
    socket.write_all(&payload).unwrap();
    socket.shutdown(Shutdown::Write).unwrap();
    let mut echoed = vec![];
    socket.read_to_end(&mut echoed).unwrap();
    assert_eq!(
        echoed, payload,
        "half-close must preserve all remaining output"
    );
}
#[test]
fn local_forward_passes_binary_and_half_close_then_releases_the_listener() {
    let Some(tools) = tools() else { return };
    let echo = Echo::start();
    let server = Server::start(&tools, &[]);
    let engine = engine();
    let session = open_session(&engine, &server);
    let forward = session
        .forward(&spec(ForwardKind::Local, echo.port))
        .unwrap();
    let port = forward.status().port;
    round_trip(socket(port));
    forward.stop();
    assert!(!forward.status().running);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(
        session.is_alive(),
        "stopping a tunnel must preserve the SSH session"
    );
}
#[test]
fn remote_forward_allocates_a_server_port_and_cancels_it_on_stop() {
    let Some(tools) = tools() else { return };
    let echo = Echo::start();
    let server = Server::start(&tools, &[]);
    let engine = engine();
    let session = open_session(&engine, &server);
    let forward = session
        .forward(&spec(ForwardKind::Remote, echo.port))
        .unwrap();
    let port = forward.status().port;
    assert_ne!(port, 0);
    round_trip(socket(port));
    forward.stop();
    assert!(!forward.status().running);
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(session.is_alive());
}
#[test]
fn socks5_sends_domains_to_the_server_and_refuses_unsupported_auth_and_udp() {
    let Some(tools) = tools() else { return };
    let echo = Echo::start();
    // PermitOpen compares the destination text. Success proves that the client
    // did not resolve localhost to an IP before sending direct-tcpip.
    let permitted = format!("PermitOpen localhost:{}", echo.port);
    let server = Server::start(&tools, &[&permitted]);
    let engine = engine();
    let session = open_session(&engine, &server);
    let forward = session.forward(&spec(ForwardKind::Dynamic, 0)).unwrap();
    let mut client = socket(forward.status().port);
    client.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    client.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    client.write_all(&[5, 1, 0, 3, 9]).unwrap();
    client.write_all(b"localhost").unwrap();
    client.write_all(&echo.port.to_be_bytes()).unwrap();
    let mut response = [0; 10];
    client.read_exact(&mut response).unwrap();
    assert_eq!(response[1], 0);
    round_trip(client);
    let mut client = socket(forward.status().port);
    client.write_all(&[5, 1, 2]).unwrap();
    client.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 255]);
    let mut client = socket(forward.status().port);
    client.write_all(&[5, 1, 0]).unwrap();
    client.read_exact(&mut greeting).unwrap();
    client
        .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 80])
        .unwrap();
    client.read_exact(&mut response).unwrap();
    assert_eq!(response[1], 7);
    assert!(forward.status().running);
    forward.stop();
}
#[test]
fn occupied_local_ports_and_denied_remote_listeners_fail_without_orphans() {
    let Some(tools) = tools() else { return };
    let server = Server::start(&tools, &["AllowTcpForwarding no"]);
    let engine = engine();
    let session = open_session(&engine, &server);
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut local = spec(ForwardKind::Local, 5432);
    local.port = occupied.local_addr().unwrap().port();
    assert!(session.forward(&local).is_err());
    assert!(session.forward(&spec(ForwardKind::Remote, 5432)).is_err());
    assert!(session.is_alive());
}
#[test]
fn stopping_a_live_tunnel_and_losing_ssh_close_streams_and_listeners() {
    let Some(tools) = tools() else { return };
    let echo = Echo::start();
    let server = Server::start(&tools, &[]);
    let engine = engine();
    let session = open_session(&engine, &server);
    let forward = session
        .forward(&spec(ForwardKind::Local, echo.port))
        .unwrap();
    let mut client = socket(forward.status().port);
    client.write_all(b"ok").unwrap();
    let mut out = [0; 2];
    client.read_exact(&mut out).unwrap();
    forward.stop();
    assert_eq!(client.read(&mut out).unwrap_or(0), 0);
    let second = session.forward(&spec(ForwardKind::Dynamic, 0)).unwrap();
    let port = second.status().port;
    session.close();
    eventually("the tunnel to notice the closed SSH transport", 3, || {
        !second.status().running
    });
    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
}
#[test]
fn local_and_remote_forwarding_use_the_destination_after_a_jump_host() {
    let Some(tools) = tools() else { return };
    let echo = Echo::start();
    let destination = Server::start(&tools, &[]);
    let permitted = format!("PermitOpen 127.0.0.1:{}", destination.sshd.port);
    let jump = Server::start(&tools, &["AllowTcpForwarding local", &permitted]);
    let auth = VaultAuth::new()
        .with_key("jump", &jump.key.private_text)
        .with_key("destination", &destination.key.private_text);
    let target = Target {
        hops: vec![
            jump.hop("jump", "jump"),
            destination.hop("destination", "destination"),
        ],
    };
    let engine = engine();
    let session = open_session_to(&engine, &target, &auth);
    for kind in [ForwardKind::Local, ForwardKind::Remote] {
        let forward = session.forward(&spec(kind, echo.port)).unwrap();
        round_trip(socket(forward.status().port));
        forward.stop();
    }
}
