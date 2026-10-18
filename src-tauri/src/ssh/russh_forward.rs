//! The engine's bounded TCP listeners and SOCKS5 CONNECT relay. No shell is opened.
use super::*;
use crate::ssh::forward::{ForwardKind, ForwardSpec, ForwardStatus, Forwarder};
use std::sync::{
    atomic::{AtomicU32, AtomicU64},
    Condvar,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinSet,
};

const LIMIT: Duration = Duration::from_secs(10);
const MAX_STREAMS: usize = 64;

struct Incoming {
    port: u32,
    channel: Channel<Msg>,
    reply: client::ChannelOpenHandle,
}
struct Route {
    id: u64,
    port: u16,
    sender: mpsc::Sender<Incoming>,
}
#[derive(Default)]
pub(super) struct Routes {
    next: AtomicU64,
    routes: Mutex<Vec<Route>>,
}
impl Routes {
    pub fn deliver(&self, port: u32, channel: Channel<Msg>, reply: client::ChannelOpenHandle) {
        let routes = locked(&self.routes);
        if let Some(route) = routes
            .iter()
            .find(|r| u32::from(r.port) == port || r.port == 0)
        {
            // Dropping a full/unregistered request rejects it. Never block russh's handler.
            let _ = route.sender.try_send(Incoming {
                port,
                channel,
                reply,
            });
        }
    }
    fn reserve(&self, port: u16) -> Result<(u64, mpsc::Receiver<Incoming>), SessionError> {
        let mut routes = locked(&self.routes);
        if routes.iter().any(|r| r.port == port) {
            return Err(SessionError::Channel(
                "A remote forward already uses this port.".into(),
            ));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(MAX_STREAMS);
        routes.push(Route { id, port, sender });
        Ok((id, receiver))
    }
    fn assign(&self, id: u64, port: u16) {
        if let Some(route) = locked(&self.routes).iter_mut().find(|r| r.id == id) {
            route.port = port;
        }
    }
    fn remove(&self, id: u64) {
        locked(&self.routes).retain(|r| r.id != id);
    }
}
struct State {
    cancel: watch::Sender<bool>,
    running: AtomicBool,
    connections: AtomicU32,
    port: u16,
    error: Mutex<Option<String>>,
    done: Mutex<bool>,
    changed: Condvar,
}
impl State {
    fn error(&self, error: impl ToString) {
        *locked(&self.error) = Some(
            error
                .to_string()
                .chars()
                .filter(|c| !c.is_control())
                .take(512)
                .collect(),
        );
    }
}
struct Running {
    state: Arc<State>,
    _runtime: Arc<RuntimeOwner>,
}
impl Forwarder for Running {
    fn status(&self) -> ForwardStatus {
        ForwardStatus {
            running: self.state.running.load(Ordering::Acquire),
            port: self.state.port,
            connections: self.state.connections.load(Ordering::Acquire),
            error: locked(&self.state.error).clone(),
        }
    }
    fn stop(&self) {
        self.state.cancel.send_replace(true);
        if tokio::runtime::Handle::try_current().is_err() {
            let _ = self.state.changed.wait_timeout_while(
                locked(&self.state.done),
                Duration::from_secs(4),
                |done| !*done,
            );
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(super) fn start(
    session: &RusshSession,
    spec: &ForwardSpec,
) -> Result<Box<dyn Forwarder>, SessionError> {
    spec.validate().map_err(SessionError::Channel)?;
    if !session.connection.is_open() {
        return Err(SessionError::Closed);
    }
    let connection = Arc::clone(&session.connection);
    let spec = spec.clone();
    let runtime = Arc::clone(&session.runtime);
    session.runtime.handle().block_on(async move {
        let destination = connection.destination()?;
        let mut route = None;
        let mut incoming = None;
        let mut listener = None;
        let port = if spec.kind == ForwardKind::Remote {
            let (id, receiver) = destination.shared.forwards.reserve(spec.port)?;
            let result = tokio::time::timeout(LIMIT, destination.handle.tcpip_forward(&spec.bind_address, u32::from(spec.port))).await;
            let assigned = match result {
                Ok(Ok(port)) => if spec.port == 0 { u16::try_from(port).ok().filter(|p| *p != 0) } else { Some(spec.port) },
                Ok(Err(error)) => { destination.shared.forwards.remove(id); return Err(channel_error(error)); }
                Err(_) => None,
            };
            let Some(port) = assigned else {
                destination.shared.forwards.remove(id);
                // A late global reply could leave a server-selected listener behind. Closing
                // the SSH transport is the only unambiguous cancellation in that case.
                connection.closing.store(true, Ordering::SeqCst);
                connection.disconnect_all().await;
                return Err(SessionError::Timeout);
            };
            destination.shared.forwards.assign(id, port);
            route = Some(id);
            incoming = Some(receiver);
            port
        } else {
            let address = std::net::SocketAddr::new(spec.bind_address.parse().unwrap(), spec.port);
            let socket = TcpListener::bind(address).await.map_err(|e| SessionError::Channel(format!("Could not listen on {address}: {e}")))?;
            let port = socket.local_addr().map_err(|e| SessionError::Channel(e.to_string()))?.port();
            listener = Some(socket);
            port
        };
        let (cancel, mut stopped) = watch::channel(false);
        let state = Arc::new(State { cancel, running: AtomicBool::new(true), connections: AtomicU32::new(0), port,
            error: Mutex::new(None), done: Mutex::new(false), changed: Condvar::new() });
        let worker = Arc::clone(&state);
        tokio::spawn(async move {
            let mut streams = JoinSet::new();
            let mut heartbeat = tokio::time::interval(Duration::from_millis(200));
            loop {
                tokio::select! {
                    biased;
                    _ = stopped.changed() => break,
                    _ = heartbeat.tick() => if !connection.is_open() {
                        worker.error("The SSH connection ended. Start the tunnel again to reconnect.");
                        break;
                    },
                    Some(_) = streams.join_next(), if !streams.is_empty() => {},
                    result = async { listener.as_ref().unwrap().accept().await }, if listener.is_some() => {
                        match result {
                            Ok((socket, _)) if streams.len() < MAX_STREAMS => {
                                let (connection, spec, state, stopped) = (Arc::clone(&connection), spec.clone(), Arc::clone(&worker), stopped.clone());
                                streams.spawn(async move { serve_local(socket, connection, spec, state, stopped).await; });
                            }
                            Ok(_) => worker.error("The tunnel has reached its concurrent connection limit."),
                            Err(error) => { worker.error(error); break; }
                        }
                    },
                    request = async { incoming.as_mut().unwrap().recv().await }, if incoming.is_some() => {
                        match request {
                            Some(request) if request.port == u32::from(port) && streams.len() < MAX_STREAMS => {
                                let (spec, state, stopped) = (spec.clone(), Arc::clone(&worker), stopped.clone());
                                streams.spawn(async move { serve_remote(request, spec, state, stopped).await; });
                            }
                            Some(_) => worker.error("An unexpected or excess remote connection was refused."),
                            None => break,
                        }
                    },
                }
            }
            // Drop the local listener before waiting for any stream/SSH cleanup.
            drop(listener);
            worker.cancel.send_replace(true);
            while streams.join_next().await.is_some() {}
            if let Some(id) = route {
                if let Ok(destination) = connection.destination() {
                    destination.shared.forwards.remove(id);
                    drop(incoming);
                    let cancelled = tokio::time::timeout(Duration::from_secs(2),
                        destination.handle.cancel_tcpip_forward(&spec.bind_address, u32::from(port))).await;
                    if !matches!(cancelled, Ok(Ok(()))) {
                        connection.closing.store(true, Ordering::SeqCst);
                        connection.disconnect_all().await;
                    }
                }
            }
            worker.running.store(false, Ordering::Release);
            *locked(&worker.done) = true;
            worker.changed.notify_all();
        });
        Ok(Box::new(Running { state, _runtime: runtime }) as Box<dyn Forwarder>)
    })
}

struct Count(Arc<State>);
impl Count {
    fn new(state: &Arc<State>) -> Self {
        state.connections.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(state))
    }
}
impl Drop for Count {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::AcqRel);
    }
}
async fn serve_local(
    mut socket: TcpStream,
    connection: Arc<Connection>,
    spec: ForwardSpec,
    state: Arc<State>,
    mut stopped: watch::Receiver<bool>,
) {
    let _count = Count::new(&state);
    let work = async {
        let destination = if spec.kind == ForwardKind::Dynamic {
            tokio::time::timeout(LIMIT, socks_request(&mut socket))
                .await
                .map_err(|_| "SOCKS5 handshake timed out.".to_string())??
        } else {
            (spec.target_host.clone(), spec.target_port)
        };
        let hop = connection.destination().map_err(|e| e.to_string())?;
        let peer = socket.peer_addr().map_err(|e| e.to_string())?;
        let opened = tokio::time::timeout(
            LIMIT,
            hop.handle.channel_open_direct_tcpip(
                &destination.0,
                u32::from(destination.1),
                peer.ip().to_string(),
                u32::from(peer.port()),
            ),
        )
        .await;
        let channel = match opened {
            Ok(Ok(channel)) => channel,
            other => {
                if spec.kind == ForwardKind::Dynamic {
                    let _ = socks_reply(&mut socket, 5).await;
                }
                return Err(match other {
                    Err(_) => "The SSH server did not open the destination in time.".into(),
                    Ok(Err(e)) => e.to_string(),
                    _ => unreachable!(),
                });
            }
        };
        let mut stream = channel.into_stream();
        if spec.kind == ForwardKind::Dynamic {
            socks_reply(&mut socket, 0)
                .await
                .map_err(|e| e.to_string())?;
        }
        tokio::io::copy_bidirectional(&mut socket, &mut stream)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    };
    tokio::select! { biased; _ = stopped.changed() => {}, result = work => if let Err(error) = result { state.error(error); } }
}
async fn serve_remote(
    request: Incoming,
    spec: ForwardSpec,
    state: Arc<State>,
    mut stopped: watch::Receiver<bool>,
) {
    let _count = Count::new(&state);
    let work = async {
        let mut socket = tokio::time::timeout(
            LIMIT,
            TcpStream::connect((spec.target_host.as_str(), spec.target_port)),
        )
        .await
        .map_err(|_| "The local destination did not respond in time.".to_string())?
        .map_err(|e| e.to_string())?;
        request.reply.accept().await;
        let mut stream = request.channel.into_stream();
        tokio::io::copy_bidirectional(&mut socket, &mut stream)
            .await
            .map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    };
    tokio::select! { biased; _ = stopped.changed() => {}, result = work => if let Err(error) = result { state.error(error); } }
}
async fn socks_reply(socket: &mut TcpStream, code: u8) -> std::io::Result<()> {
    socket.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
async fn socks_request(socket: &mut TcpStream) -> Result<(String, u16), String> {
    async fn parse(socket: &mut TcpStream) -> std::io::Result<(String, u16)> {
        let version = socket.read_u8().await?;
        let count = socket.read_u8().await?;
        if version != 5 || count == 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let mut methods = vec![0; usize::from(count)];
        socket.read_exact(&mut methods).await?;
        if !methods.contains(&0) {
            socket.write_all(&[5, 255]).await?;
            return Err(std::io::ErrorKind::PermissionDenied.into());
        }
        socket.write_all(&[5, 0]).await?;
        let mut header = [0; 4];
        socket.read_exact(&mut header).await?;
        if header[0] != 5 || header[1] != 1 || header[2] != 0 {
            socks_reply(socket, 7).await?;
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        let host = match header[3] {
            1 => {
                let mut ip = [0; 4];
                socket.read_exact(&mut ip).await?;
                std::net::Ipv4Addr::from(ip).to_string()
            }
            4 => {
                let mut ip = [0; 16];
                socket.read_exact(&mut ip).await?;
                std::net::Ipv6Addr::from(ip).to_string()
            }
            3 => {
                let count = socket.read_u8().await?;
                let mut name = vec![0; usize::from(count)];
                socket.read_exact(&mut name).await?;
                let name = String::from_utf8(name).map_err(|_| std::io::ErrorKind::InvalidData)?;
                if name.is_empty() || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                name
            }
            _ => {
                socks_reply(socket, 8).await?;
                return Err(std::io::ErrorKind::InvalidData.into());
            }
        };
        let port = socket.read_u16().await?;
        if port == 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        // Domain names travel to the SSH server unchanged; DNS is resolved remotely.
        Ok((host, port))
    }
    parse(socket)
        .await
        .map_err(|e| format!("SOCKS5 connection refused: {e}"))
}
