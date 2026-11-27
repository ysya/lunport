//! Verified PostgreSQL TLS on a direct socket or the loopback end of a saved SSH route.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::FutureExt;
use rustls::{client::Resumption, pki_types::ServerName, ClientConfig, RootCertStore};
use tauri::Manager;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::auth::label;
use super::auth_window::{NativeOwner, TauriAuthSurface};
use super::connect::{CancelToken, Connected};
use super::database_console::{cancelled, CancelDial, CANCEL_WITHIN, SIGN_IN_WITHIN};
use super::database_path::HostPath;
use super::database_ports::BoxStream;
use super::databases::started_broker;
use super::protocol::HostQuery;
use super::standard_postgres_profiles::{check_ssh_target, StandardPostgresProfile};
use crate::state::AppState;

const OPEN_CANCELLED: &str = "The database connection was cancelled.";
// PostgreSQL protocol SSLRequest: length 8 followed by request code 80877103.
const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 4, 210, 22, 47];

/// The cancel stream owns this hold until its final packet has been sent and the stream is dropped,
/// even if the console and the cancel dial closure go away first.
struct RoutedSocket {
    stream: TcpStream,
    _path: Option<Arc<HostPath>>,
}

impl AsyncRead for RoutedSocket {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for RoutedSocket {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct Forward {
    path: Arc<HostPath>,
    port: u16,
}

/// Cancellation reuses the active route and original certificate identity. For direct DNS, the peer
/// is the actual address that was dialled. For SSH, the peer is this path's existing loopback port.
#[derive(Clone)]
struct CancelRoute {
    peer: SocketAddr,
    forward: Option<Arc<HostPath>>,
    config: TlsConnector,
    name: ServerName<'static>,
}

impl CancelRoute {
    fn dial(self) -> CancelDial {
        Arc::new(move || {
            let route = self.clone();
            async move {
                bounded(CANCEL_WITHIN, async move {
                    if let Some(path) = &route.forward {
                        check_path(path)?;
                    }
                    let socket = TcpStream::connect(route.peer).await?;
                    tls(socket, route.forward, &route.config, route.name).await
                })
                .await
            }
            .boxed()
        })
    }
}

/// The OS trust store is read at each open so newly installed private roots can be used on the next connection.
fn system_tls() -> io::Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    tls_config(roots)
}

fn tls_config(roots: RootCertStore) -> io::Result<TlsConnector> {
    if roots.is_empty() {
        return Err(io::Error::other("No system root certificates could be loaded."));
    }
    // Both aws-lc-rs and ring are linked into the app. Name the provider explicitly.
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // The cancel socket must verify the certificate it receives on its own handshake.
    config.resumption = Resumption::disabled();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn tls(
    socket: TcpStream,
    path: Option<Arc<HostPath>>,
    config: &TlsConnector,
    name: ServerName<'static>,
) -> io::Result<BoxStream> {
    let _ = socket.set_nodelay(true);
    let mut socket = RoutedSocket {
        stream: socket,
        _path: path,
    };
    socket.write_all(&SSL_REQUEST).await?;
    match socket.read_u8().await? {
        b'S' => {}
        b'N' => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "The PostgreSQL server refused TLS.",
            ))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "The PostgreSQL server sent an invalid TLS negotiation response.",
            ))
        }
    }
    let secured = config
        .connect(name, socket)
        .await
        .map_err(|error| io::Error::new(error.kind(), format!("PostgreSQL TLS verification failed: {error}")))?;
    Ok(Box::new(secured))
}

fn check_path(path: &HostPath) -> io::Result<()> {
    if path.alive() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "The PostgreSQL SSH route is no longer open. Connect again.",
        ))
    }
}

async fn bounded<T>(duration: Duration, operation: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(duration, operation).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "The PostgreSQL server did not complete the connection in time.",
        )
    })?
}

async fn connect(
    host: &str,
    port: u16,
    forward: Option<Forward>,
    config: TlsConnector,
    within: Duration,
) -> io::Result<(BoxStream, CancelDial)> {
    let name = ServerName::try_from(host.to_owned()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "The PostgreSQL host must be a DNS name or IP address.",
        )
    })?;
    bounded(within, async {
        let (socket, forward) = match forward {
            Some(Forward { path, port }) => {
                check_path(&path)?;
                (TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?, Some(path))
            }
            None => (TcpStream::connect((host, port)).await?, None),
        };
        let peer = socket.peer_addr()?;
        let stream = tls(socket, forward.clone(), &config, name.clone()).await?;
        Ok((
            stream,
            CancelRoute {
                peer,
                forward,
                config,
                name,
            }
            .dial(),
        ))
    })
    .await
}

fn prepare_forward(
    open: impl FnOnce() -> Result<HostPath, String>,
    host: &str,
    port: u16,
    cancel: &CancelToken,
) -> Result<Forward, String> {
    if cancel.is_cancelled() {
        return Err(OPEN_CANCELLED.into());
    }
    let mut path = open()?;
    if cancel.is_cancelled() {
        return Err(OPEN_CANCELLED.into());
    }
    let port = path.forward_to(host, port).map_err(|error| {
        format!(
            "Could not open the PostgreSQL forward through {}: {error}",
            label(path.alias())
        )
    })?;
    Ok(Forward {
        path: Arc::new(path),
        port,
    })
}

fn open_host(
    app: &tauri::AppHandle,
    profile: &StandardPostgresProfile,
    host_id: &str,
    cancel: &CancelToken,
) -> Result<HostPath, String> {
    static REQUESTS: AtomicU64 = AtomicU64::new(0);
    let broker = started_broker(app)?;
    let owner = NativeOwner {
        ai: None,
        hub: app.state::<AppState>().session.auth_questions.clone(),
        surface: Arc::new(TauriAuthSurface { app: app.clone() }),
        request_id: format!("postgresql-{}", REQUESTS.fetch_add(1, Ordering::Relaxed)),
        cancel: cancel.clone(),
    };
    let Connected { session, target } = broker
        .connector()
        .connect(&HostQuery::Id(host_id.to_owned()), &owner, cancel)
        .map_err(|failure| failure.text)?;
    let alias = target.hops.last().map_or_else(|| host_id.to_owned(), |hop| hop.alias.clone());
    let path = HostPath::new(session, alias);
    check_ssh_target(app, profile, &target)?;
    Ok(path)
}

struct CancelWorker(CancelToken);

impl Drop for CancelWorker {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn during_open<T>(cancel: &CancelToken, operation: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::select! {
        biased;
        () = cancelled(cancel) => Err(OPEN_CANCELLED.into()),
        result = operation => result,
    }
}

/// Opens a password-free, verified TLS stream and freezes the route used by future CancelRequests.
/// The PostgreSQL driver above this stream must use SslMode::Disable when using NoTls.
pub(crate) async fn open(
    app: &tauri::AppHandle,
    profile: &StandardPostgresProfile,
    cancel: &CancelToken,
) -> Result<(BoxStream, CancelDial), String> {
    // A dropped open also stops anything the background owner is still waiting to learn.
    let worker = CancelWorker(CancelToken::default());
    during_open(cancel, async {
        let host = &profile.host;
        let port = profile.port;
        let (app, profile, worker_cancel) = (app.clone(), profile.clone(), worker.0.clone());
        let (forward, config) = tokio::task::spawn_blocking(move || -> Result<_, String> {
            let config = system_tls().map_err(|error| error.to_string())?;
            let forward = profile
                .via_host
                .as_deref()
                .map(|host_id| {
                    prepare_forward(
                        || open_host(&app, &profile, host_id, &worker_cancel),
                        &profile.host,
                        profile.port,
                        &worker_cancel,
                    )
                })
                .transpose()?;
            Ok((forward, config))
        })
        .await
        .map_err(|error| error.to_string())??;
        connect(host, port, forward, config, SIGN_IN_WITHIN)
            .await
            .map_err(|error| format!("Could not connect to PostgreSQL: {error}"))
    })
    .await
}

#[cfg(test)]
async fn open_with_roots(
    host: &str,
    port: u16,
    roots: RootCertStore,
) -> Result<(BoxStream, CancelDial), String> {
    let config = tls_config(roots).map_err(|error| error.to_string())?;
    connect(host, port, None, config, SIGN_IN_WITHIN)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "postgres_transport_tests.rs"]
mod tests;
