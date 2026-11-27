use super::*;
use crate::session::pg_fake::frame;
use crate::ssh::forward::{ForwardKind, ForwardSpec, ForwardStatus, Forwarder};
use crate::ssh::{DisconnectReason, ExecResult, Pty, Session, SessionError, ShellChannel};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tokio::net::TcpListener;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

const REMOTE_HOST: &str = "postgres.invalid";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn certificates(san: &str) -> (RootCertStore, TlsAcceptor) {
    let mut authority = CertificateParams::default();
    authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let authority = CertifiedIssuer::self_signed(authority, KeyPair::generate().unwrap()).unwrap();
    let leaf = CertificateParams::new(vec![san.into()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = leaf.signed_by(&key, &authority).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(authority.der().clone()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    (roots, TlsAcceptor::from(Arc::new(server)))
}

async fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

async fn ssl_request(listener: &TcpListener) -> TcpStream {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut prefix = [0; 8];
    stream.read_exact(&mut prefix).await.unwrap();
    assert_eq!(prefix, [0, 0, 0, 8, 4, 210, 22, 47]);
    stream
}

async fn accept_tls(listener: &TcpListener, acceptor: &TlsAcceptor) -> io::Result<TlsStream<TcpStream>> {
    let mut stream = ssl_request(listener).await;
    stream.write_all(b"S").await?;
    acceptor.accept(stream).await
}

#[tokio::test]
async fn requires_ssl_acceptance_without_sending_any_cleartext_startup() {
    for (reply, kind) in [
        (Some(b'N'), io::ErrorKind::Unsupported),
        (Some(b'!'), io::ErrorKind::InvalidData),
        (None, io::ErrorKind::UnexpectedEof),
    ] {
        let (listener, port) = listener().await;
        let config = tls_config(certificates("127.0.0.1").0).unwrap();
        let server = tokio::spawn(async move {
            let mut stream = ssl_request(&listener).await;
            if let Some(reply) = reply {
                stream.write_u8(reply).await.unwrap();
            } else {
                stream.shutdown().await.unwrap();
            }
            assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
        });
        let failed = connect("127.0.0.1", port, None, config, TEST_TIMEOUT).await.err().unwrap();
        assert_eq!(failed.kind(), kind);
        tokio::time::timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn rejects_unknown_authority_and_wrong_dns_or_ip_san() {
    for (endpoint, san, unknown_ca) in [
        ("localhost", "localhost", true),
        ("localhost", REMOTE_HOST, false),
        ("127.0.0.1", "localhost", false),
    ] {
        let (listener, port) = listener().await;
        let (roots, acceptor) = certificates(san);
        let config = tls_config(if unknown_ca { certificates(san).0 } else { roots }).unwrap();
        let server = tokio::spawn(async move {
            assert!(accept_tls(&listener, &acceptor).await.is_err());
        });
        let failed = connect(endpoint, port, None, config, TEST_TIMEOUT).await.err().unwrap();
        assert!(failed.to_string().starts_with("PostgreSQL TLS verification failed"));
        tokio::time::timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn times_out_while_waiting_for_the_ssl_response_or_tls_handshake() {
    for accepted in [false, true] {
        let (listener, port) = listener().await;
        let config = tls_config(certificates("127.0.0.1").0).unwrap();
        let server = tokio::spawn(async move {
            let mut stream = ssl_request(&listener).await;
            if accepted {
                stream.write_all(b"S").await.unwrap();
            }
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received.is_empty(), !accepted);
        });
        let failed = connect("127.0.0.1", port, None, config, Duration::from_millis(300))
            .await
            .err()
            .unwrap();
        assert_eq!(failed.kind(), io::ErrorKind::TimedOut);
        tokio::time::timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn canceling_an_open_closes_a_pending_ssl_socket() {
    let (listener, port) = listener().await;
    let config = tls_config(certificates("127.0.0.1").0).unwrap();
    let cancel = CancelToken::default();
    let server_cancel = cancel.clone();
    let server = tokio::spawn(async move {
        let mut stream = ssl_request(&listener).await;
        server_cancel.cancel();
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let opened = during_open(&cancel, async {
        connect("127.0.0.1", port, None, config, TEST_TIMEOUT)
            .await
            .map_err(|error| error.to_string())
    })
    .await;
    assert_eq!(opened.err().as_deref(), Some(OPEN_CANCELLED));
    tokio::time::timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
}

#[tokio::test]
async fn verifies_tls_before_startup_password_and_cancel_on_direct_dns_ip_or_forward() {
    for (host, via) in [("localhost", false), ("127.0.0.1", false), (REMOTE_HOST, true)] {
        let (listener, port) = listener().await;
        let (roots, acceptor) = certificates(host);
        let fake = Arc::new(FakeHost::new(port));
        let forward = via.then(|| prepare_forward(|| Ok(fake.path()), host, 15432, &CancelToken::default()).unwrap());
        let server = tokio::spawn(async move {
            let mut startup = accept_tls(&listener, &acceptor).await.unwrap();
            let expected_sni = (host != "127.0.0.1").then_some(host);
            assert_eq!(startup.get_ref().1.server_name(), expected_sni);
            let size = startup.read_u32().await.unwrap() as usize;
            assert!((8..1024).contains(&size));
            let mut message = vec![0; size - 4];
            startup.read_exact(&mut message).await.unwrap();
            assert_eq!(&message[..4], &196608u32.to_be_bytes());
            assert!(message.windows(10).any(|window| window == b"user\0frank"));
            startup.write_all(&frame(b'R', &3u32.to_be_bytes())).await.unwrap();
            startup.flush().await.unwrap();
            assert_eq!(startup.read_u8().await.unwrap(), b'p');
            assert_eq!(startup.read_u32().await.unwrap(), 14);
            let mut password = [0; 10];
            startup.read_exact(&mut password).await.unwrap();
            assert!(password == *b"test-pass\0");
            let key_data = [0, 0, 0, 7, 0, 0, 0, 11];
            startup.write_all(&frame(b'R', &0u32.to_be_bytes())).await.unwrap();
            startup.write_all(&frame(b'K', &key_data)).await.unwrap();
            startup.write_all(&frame(b'Z', b"I")).await.unwrap();
            startup.flush().await.unwrap();

            let mut cancel = accept_tls(&listener, &acceptor).await.unwrap();
            assert_eq!(cancel.get_ref().1.server_name(), expected_sni);
            let mut message = [0; 16];
            cancel.read_exact(&mut message).await.unwrap();
            assert_eq!(&message[..8], &[0, 0, 0, 16, 4, 210, 22, 46]);
            assert!(message[8..] == key_data);
            cancel.shutdown().await.unwrap();
        });
        let (stream, cancel_dial) = match forward {
            Some(forward) => connect(host, port, Some(forward), tls_config(roots).unwrap(), TEST_TIMEOUT)
                .await
                .unwrap(),
            None => tokio::time::timeout(TEST_TIMEOUT, open_with_roots(host, port, roots))
                .await
                .unwrap()
                .unwrap(),
        };
        let mut login = tokio_postgres::Config::new();
        login
            .user("frank")
            .dbname("db")
            .password("test-pass")
            .ssl_mode(tokio_postgres::config::SslMode::Disable);
        let (client, connection) = tokio::time::timeout(TEST_TIMEOUT, login.connect_raw(stream, tokio_postgres::NoTls))
            .await
            .unwrap()
            .unwrap();
        let cancel = client.cancel_token();
        let cancelling = cancel_dial();
        drop(cancel_dial);
        drop(client);
        drop(connection);
        if via {
            let forwards = fake.forwards.lock().unwrap();
            assert_eq!(
                forwards.as_slice(),
                &[ForwardSpec {
                    kind: ForwardKind::Local,
                    bind_address: "127.0.0.1".into(),
                    port: 0,
                    target_host: host.into(),
                    target_port: 15432
                }]
            );
            assert!(!fake.closed.load(Ordering::SeqCst));
        }
        let mut stream = cancelling.await.unwrap();
        if via {
            assert!(!fake.closed.load(Ordering::SeqCst));
        }
        tokio::time::timeout(TEST_TIMEOUT, cancel.cancel_query_raw(&mut stream, tokio_postgres::NoTls))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
        drop(stream);
        if via {
            fake.assert_released();
        }
    }
}

#[tokio::test]
async fn forward_rejects_loopback_identity_and_closes_session_and_listener() {
    let (listener, port) = listener().await;
    let (roots, acceptor) = certificates("127.0.0.1");
    let config = tls_config(roots).unwrap();
    let fake = Arc::new(FakeHost::new(port));
    let forward = prepare_forward(|| Ok(fake.path()), REMOTE_HOST, 5432, &CancelToken::default()).unwrap();
    let server = tokio::spawn(async move {
        assert!(accept_tls(&listener, &acceptor).await.is_err());
    });
    let failure = connect(REMOTE_HOST, 5432, Some(forward), config, TEST_TIMEOUT)
        .await
        .err()
        .unwrap();
    assert!(failure.to_string().starts_with("PostgreSQL TLS verification failed"));
    tokio::time::timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    fake.assert_released();
}

#[tokio::test]
async fn a_timed_out_forwarded_dial_releases_the_route() {
    let (listener, port) = listener().await;
    let config = tls_config(certificates(REMOTE_HOST).0).unwrap();
    let fake = Arc::new(FakeHost::new(port));
    let forward = prepare_forward(|| Ok(fake.path()), REMOTE_HOST, 5432, &CancelToken::default()).unwrap();
    let server = tokio::spawn(async move {
        let mut stream = ssl_request(&listener).await;
        assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    });
    let failure = connect(REMOTE_HOST, 5432, Some(forward), config, Duration::from_millis(300))
        .await
        .err()
        .unwrap();
    assert_eq!(failure.kind(), io::ErrorKind::TimedOut);
    tokio::time::timeout(TEST_TIMEOUT, server).await.unwrap().unwrap();
    fake.assert_released();
}

#[tokio::test]
async fn cancellation_never_dials_directly_after_the_saved_route_ends() {
    let (forward_listener, forward_port) = listener().await;
    let (direct_listener, direct_port) = listener().await;
    let (roots, acceptor) = certificates("127.0.0.1");
    let fake = Arc::new(FakeHost::new(forward_port));
    let forward = prepare_forward(|| Ok(fake.path()), "127.0.0.1", direct_port, &CancelToken::default()).unwrap();
    let startup = tokio::spawn(async move {
        let startup = accept_tls(&forward_listener, &acceptor).await.unwrap();
        (startup, forward_listener)
    });
    let (stream, cancel_dial) = connect(
        "127.0.0.1",
        direct_port,
        Some(forward),
        tls_config(roots).unwrap(),
        TEST_TIMEOUT,
    )
    .await
    .unwrap();
    let (_startup, forward_listener) = tokio::time::timeout(TEST_TIMEOUT, startup).await.unwrap().unwrap();
    fake.closed.store(true, Ordering::SeqCst);
    let failure = tokio::time::timeout(TEST_TIMEOUT, cancel_dial())
        .await
        .unwrap()
        .err()
        .unwrap();
    assert_eq!(failure.kind(), io::ErrorKind::NotConnected);
    // Each listener would immediately accept any connection already made to it.
    tokio::select! {
        biased;
        _ = direct_listener.accept() => panic!("Cancel dialled the database directly"),
        _ = forward_listener.accept() => panic!("Cancel reused a dead route"),
        _ = std::future::ready(()) => {}
    }
    drop(cancel_dial);
    drop(stream);
    fake.assert_released();
}

#[test]
fn opening_a_cancelled_host_does_not_start_a_forward() {
    let fake = Arc::new(FakeHost::new(15432));
    let cancel = CancelToken::default();
    let forward = prepare_forward(
        || {
            cancel.cancel();
            Ok(fake.path())
        },
        REMOTE_HOST,
        5432,
        &cancel,
    );
    assert_eq!(forward.err().as_deref(), Some(OPEN_CANCELLED));
    assert!(fake.forwards.lock().unwrap().is_empty());
    crate::ssh::testing::eventually("the cancelled session to close", 2, || fake.closed.load(Ordering::SeqCst));
}

#[test]
fn refused_forward_closes_the_host_session() {
    let fake = Arc::new(FakeHost::new(0));
    let refused = prepare_forward(|| Ok(fake.path()), REMOTE_HOST, 5432, &CancelToken::default());
    assert!(refused.err().unwrap().contains("Forward refused."));
    crate::ssh::testing::eventually("the refused session to close", 2, || fake.closed.load(Ordering::SeqCst));
}

/// The fixture server plays the loopback side of this SSH path. Its destination name exists only on the fake host.
struct FakeHost {
    port: u16,
    forwards: Mutex<Vec<ForwardSpec>>,
    stopped: AtomicBool,
    closed: AtomicBool,
}

impl FakeHost {
    fn new(port: u16) -> Self {
        Self {
            port,
            forwards: Mutex::default(),
            stopped: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    fn path(self: &Arc<Self>) -> HostPath {
        HostPath::new(Box::new(FakeSession(self.clone())), "web-1".into())
    }

    fn assert_released(&self) {
        crate::ssh::testing::eventually("the forward and host session to close", 2, || {
            self.stopped.load(Ordering::SeqCst) && self.closed.load(Ordering::SeqCst)
        });
    }
}

struct FakeSession(Arc<FakeHost>);

impl Session for FakeSession {
    fn forward(&self, spec: &ForwardSpec) -> Result<Box<dyn Forwarder>, SessionError> {
        self.0.forwards.lock().unwrap().push(spec.clone());
        if self.0.port == 0 {
            return Err(SessionError::Channel("Forward refused.".into()));
        }
        Ok(Box::new(FakeForwarder(self.0.clone())))
    }

    fn shell(&self, _: Pty) -> Result<Box<dyn ShellChannel>, SessionError> {
        unreachable!()
    }

    fn exec(&self, _: &str, _: Duration, _: usize) -> Result<ExecResult, SessionError> {
        unreachable!()
    }

    fn is_alive(&self) -> bool {
        !self.0.closed.load(Ordering::SeqCst)
    }

    fn disconnect_reason(&self) -> Option<DisconnectReason> {
        None
    }

    fn close(&self) {
        self.0.closed.store(true, Ordering::SeqCst);
    }
}

struct FakeForwarder(Arc<FakeHost>);

impl Forwarder for FakeForwarder {
    fn status(&self) -> ForwardStatus {
        ForwardStatus {
            running: !self.0.stopped.load(Ordering::SeqCst),
            port: self.0.port,
            ..ForwardStatus::default()
        }
    }

    fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
    }
}
