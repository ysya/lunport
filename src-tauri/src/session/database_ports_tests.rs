//! The local port of a saved database as the apps that connect to it see it: what reaches Cloud SQL, what is refused and why, and how the
//! port starts and stops. A fake upstream stands for Cloud SQL (a `tokio::io::duplex` pipe to a scripted server). The Cloud SQL upstream's
//! own tests use the app, the fake Cloud SQL and the clock from here.

use super::*;
use crate::session::databases::DatabasePhase;
use crate::sync::databases::tests::database;
use crate::sync::databases::DatabaseEnvironment;
use crate::sync::testkit::MemKeychain;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

pub(crate) const ID: &str = "00000000000000d1";
const OTHER: &str = "00000000000000d2";
/// The password the tests' ports are started with.
pub(crate) const PASSWORD: &str = "c2VjcmV0LXBvcnQtcGFzc3dvcmQtMDEy";
pub(crate) const IAM_USER: &str = "frank@example.com";
pub(crate) const CONNECTION: &str = "acme-prod-123456:asia-east1:orders-pg";
const EXPIRED: &str = "Google sign-in for frank@example.com has expired or was revoked; run `gcloud auth login frank@example.com` and connect again.";
/// How long a test waits for anything the port does.
pub(crate) const LIMIT: Duration = Duration::from_secs(10);
/// Protocol version 3.0 and 3.2, as a start-up message carries them.
const PROTOCOL_3_0: u32 = 196608;
const PROTOCOL_3_2: u32 = 196610;
const SSL_REQUEST: u32 = 80877103;
const GSSENC_REQUEST: u32 = 80877104;
const CANCEL_REQUEST: u32 = 80877102;
const LOCK: &str = "-c cloudsql_session_read_only=locked";

/// The prod database of the fixtures, `Orders`, offered on a port the system picks.
pub(crate) fn orders() -> SavedDatabase {
    SavedDatabase { local_port: Some(0), ..database(ID) }
}

// ---- The wire, written out byte by byte apart from the codec ----

/// A start-up message: its length (which counts itself), the protocol version, each parameter as two texts that end with a zero byte, and a
/// last zero byte.
fn startup_wire(version: u32, pairs: &[(&str, &str)]) -> Vec<u8> {
    let mut body = version.to_be_bytes().to_vec();
    for (name, value) in pairs {
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
    }
    body.push(0);
    let mut message = ((body.len() + 4) as u32).to_be_bytes().to_vec();
    message.extend_from_slice(&body);
    message
}

/// A message with a type byte: the type, a length that counts itself and not the type byte, and `body`.
fn typed(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![kind];
    message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    message.extend_from_slice(body);
    message
}

/// A request that is a length of 8 and a code: SSLRequest or GSSENCRequest.
fn request(code: u32) -> Vec<u8> {
    [8u32.to_be_bytes(), code.to_be_bytes()].concat()
}

/// A CancelRequest for the session with process id 4242 and the secret key 0x0badcafe.
pub(crate) fn cancel_request() -> Vec<u8> {
    [16u32.to_be_bytes(), CANCEL_REQUEST.to_be_bytes(), 4242u32.to_be_bytes(), 0x0bad_cafe_u32.to_be_bytes()].concat()
}

// ---- Cloud SQL, faked ----

/// How the fake Cloud SQL answers a start-up message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Answer {
    /// AuthenticationOk and ReadyForQuery `I`; then it sends back whatever it is sent.
    #[default]
    SignsIn,
    /// AuthenticationCleartextPassword, as an instance without IAM database authentication answers an IAM user.
    AsksForPassword,
    /// It closes the connection without a word, as an instance does when it refuses the client certificate.
    HangsUp,
}

/// Cloud SQL at the far end of `stream`: it records the first message it gets as it came, answers a start-up message as `answer` says
/// and takes a cancel request without a word.
pub(crate) async fn fake_cloud_sql(mut stream: DuplexStream, answer: Answer, received: Arc<Mutex<Vec<Vec<u8>>>>) {
    let mut length = [0u8; 4];
    if stream.read_exact(&mut length).await.is_err() {
        return;
    }
    let mut message = length.to_vec();
    message.resize((u32::from_be_bytes(length) as usize).max(4), 0);
    if stream.read_exact(&mut message[4..]).await.is_err() {
        return;
    }
    let cancel = message.get(4..8) == Some(&CANCEL_REQUEST.to_be_bytes()[..]);
    received.lock().unwrap().push(message);
    if cancel {
        return;
    }
    match answer {
        Answer::HangsUp => {}
        Answer::AsksForPassword => {
            if stream.write_all(&typed(b'R', &3u32.to_be_bytes())).await.is_ok() {
                // The password never comes: Lunport refuses the app and hangs up.
                let _ = stream.read(&mut [0u8; 1]).await;
            }
        }
        Answer::SignsIn => {
            let mut signed_in = typed(b'R', &0u32.to_be_bytes());
            signed_in.extend(typed(b'Z', b"I"));
            if stream.write_all(&signed_in).await.is_err() {
                return;
            }
            let mut buffer = [0u8; 4096];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => {
                        if stream.write_all(&buffer[..read]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// An upstream for the port's own tests: `prepare` answers `frank@example.com` (or the sentence it is told to fail with), and `connect`
/// pipes to a `fake_cloud_sql` that answers as `answer` says. What it was asked to do is counted.
#[derive(Default)]
pub(crate) struct FakeUpstream {
    /// `prepare` fails with this sentence.
    pub refusing: Mutex<Option<String>>,
    /// `prepare` waits until its connection is cancelled, as a question nobody answers does.
    pub waiting: AtomicBool,
    pub answer: Mutex<Answer>,
    /// `connect` fails.
    pub unreachable: AtomicBool,
    pub prepared: AtomicUsize,
    /// How many `prepare` calls gave up because their connection was cancelled.
    pub cancelled: AtomicUsize,
    pub dialled: AtomicUsize,
    pub forgotten: AtomicUsize,
    pub released: AtomicUsize,
    /// The first message each connection to the fake Cloud SQL carried, as it came.
    pub received: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl FakeUpstream {
    pub(crate) fn received(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }
}

impl Upstream for FakeUpstream {
    fn prepare(&self, _db: &SavedDatabase, cancel: &CancelToken) -> Result<String, String> {
        self.prepared.fetch_add(1, Ordering::SeqCst);
        if self.waiting.load(Ordering::SeqCst) {
            let end = Instant::now() + LIMIT;
            while !cancel.is_cancelled() && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            self.cancelled.fetch_add(1, Ordering::SeqCst);
            return Err("The connection was cancelled.".into());
        }
        match self.refusing.lock().unwrap().clone() {
            Some(sentence) => Err(sentence),
            None => Ok(IAM_USER.into()),
        }
    }

    fn connect(&self, _db_id: &str) -> Dialling {
        let material = self.dialled.fetch_add(1, Ordering::SeqCst) as u64 + 1;
        let unreachable = self.unreachable.load(Ordering::SeqCst);
        let answer = *self.answer.lock().unwrap();
        let received = Arc::clone(&self.received);
        let stream: BoxFuture<'static, io::Result<BoxStream>> = Box::pin(async move {
            if unreachable {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "Cloud SQL refused the connection."));
            }
            let (near, far) = tokio::io::duplex(64 * 1024);
            tokio::spawn(fake_cloud_sql(far, answer, received));
            Ok(Box::new(near) as BoxStream)
        });
        Dialling { material: Some(material), stream }
    }

    fn forget(&self, _db_id: &str, _material: u64) {
        self.forgotten.fetch_add(1, Ordering::SeqCst);
    }

    fn release(&self, _db_id: &str) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

// ---- An app ----

/// An app that connects to the port as psql or DataGrip does: plain TCP on 127.0.0.1, every read bounded by `LIMIT`.
pub(crate) struct App(std::net::TcpStream);

impl App {
    pub(crate) fn connect(port: u16) -> App {
        let stream = std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("the port takes connections");
        stream.set_read_timeout(Some(LIMIT)).unwrap();
        App(stream)
    }

    /// An app signed in to the port with `PASSWORD`, as `frank` on `orders`.
    pub(crate) fn signed_in(port: u16) -> App {
        let mut app = App::connect(port);
        app.startup(&[("user", "frank"), ("database", "orders")]);
        app.sign_in(PASSWORD);
        app
    }

    pub(crate) fn send(&mut self, bytes: &[u8]) {
        self.0.write_all(bytes).expect("the port reads");
    }

    pub(crate) fn startup(&mut self, pairs: &[(&str, &str)]) {
        self.send(&startup_wire(PROTOCOL_3_0, pairs));
    }

    /// Answers Lunport's request for the password with `password` and expects to be signed in: Cloud SQL's AuthenticationOk and
    /// ReadyForQuery, passed on.
    pub(crate) fn sign_in(&mut self, password: &str) {
        self.asked_for_password();
        self.password(password);
        assert_eq!(self.message(), (b'R', 0u32.to_be_bytes().to_vec()), "signed in");
        assert_eq!(self.message(), (b'Z', b"I".to_vec()), "ready for a query");
    }

    pub(crate) fn asked_for_password(&mut self) {
        assert_eq!(self.message(), (b'R', 3u32.to_be_bytes().to_vec()), "Lunport asks for the password in clear text");
    }

    pub(crate) fn password(&mut self, password: &str) {
        let mut body = password.as_bytes().to_vec();
        body.push(0);
        self.send(&typed(b'p', &body));
    }

    fn bytes(&mut self, count: usize) -> Vec<u8> {
        let mut buffer = vec![0u8; count];
        self.0.read_exact(&mut buffer).expect("the port answers in time");
        buffer
    }

    /// The next message from the port: its type and its body.
    fn message(&mut self) -> (u8, Vec<u8>) {
        let head = self.bytes(5);
        let length = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
        (head[0], self.bytes(length - 4))
    }

    /// The SQLSTATE and the message of the ErrorResponse that comes next, which is fatal.
    pub(crate) fn error(&mut self) -> (String, String) {
        let (kind, body) = self.message();
        assert_eq!(kind, b'E', "an ErrorResponse: {:?}", String::from_utf8_lossy(&body));
        let mut fields = BTreeMap::new();
        let mut rest = &body[..];
        while let Some((&field, after)) = rest.split_first() {
            if field == 0 {
                break;
            }
            let end = after.iter().position(|byte| *byte == 0).expect("a field ends with a zero byte");
            fields.insert(field, String::from_utf8(after[..end].to_vec()).unwrap());
            rest = &after[end + 1..];
        }
        assert_eq!(fields.get(&b'S').map(String::as_str), Some("FATAL"));
        (fields.remove(&b'C').expect("a SQLSTATE"), fields.remove(&b'M').expect("a message"))
    }

    /// Whether the port closed the connection: a read finds its end, or finds it reset.
    pub(crate) fn closed(&mut self) -> bool {
        match self.0.read(&mut [0u8; 1]) {
            Ok(0) => true,
            Ok(_) => false,
            Err(error) => matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe),
        }
    }

    /// Whether the port ended the connection, with an ErrorResponse before or without one: what comes is read to its end.
    fn ended(&mut self) -> bool {
        let mut rest = Vec::new();
        match self.0.read_to_end(&mut rest) {
            Ok(_) => rest.first().is_none_or(|kind| *kind == b'E'),
            Err(error) => matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe),
        }
    }

    /// Sends `bytes` through the port and expects them back: the fake Cloud SQL sends back what it gets.
    pub(crate) fn round_trip(&mut self, bytes: &[u8]) {
        self.send(bytes);
        assert_eq!(self.bytes(bytes.len()), bytes, "the port relays both ways");
    }
}

/// Waits until `done`, at most `LIMIT`.
pub(crate) fn wait_until(what: &str, done: impl Fn() -> bool) {
    let end = Instant::now() + LIMIT;
    while !done() {
        assert!(Instant::now() < end, "timed out waiting until {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Starts `db` on `ports` with `PASSWORD` and answers the port it listens on.
pub(crate) fn running(ports: &DatabasePorts, db: &SavedDatabase) -> u16 {
    ports.start(db, Zeroizing::new(PASSWORD.into()), CancelToken::default(), Box::new(())).expect("the port starts");
    let live = ports.live(&db.id);
    assert_eq!(live.phase, DatabasePhase::Running);
    live.port.expect("a running port has a port")
}

fn fake() -> Arc<FakeUpstream> {
    Arc::new(FakeUpstream::default())
}

// ---- Signing in ----

#[test]
fn a_wrong_password_is_refused_before_cloud_sql_is_contacted() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut app = App::connect(port);
    app.startup(&[("user", "frank"), ("database", "orders")]);
    app.asked_for_password();
    app.password("c2VjcmV0LXBvcnQtcGFzc3dvcmQtMDEz");
    assert_eq!(app.error(), ("28P01".to_string(), "Wrong password for Orders. Copy the password from Lunport.".to_string()));
    assert!(app.closed());
    assert_eq!(upstream.prepared.load(Ordering::SeqCst), 0, "nothing was asked of Google");
    assert_eq!(upstream.dialled.load(Ordering::SeqCst), 0, "Cloud SQL was not dialled");
    // The right password gets in.
    App::signed_in(port).round_trip(b"select 1");
}

#[test]
fn the_startup_reaches_cloud_sql_with_the_iam_user_and_the_prod_lock() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut app = App::connect(port);
    // The app's own options are kept; a separate setting that would undo the lock is not.
    app.startup(&[("user", "frank"), ("database", "orders"), ("application_name", "psql"), ("options", "-c search_path=sales"), ("cloudsql_session_read_only", "off")]);
    app.sign_in(PASSWORD);
    app.round_trip(b"select count(*) from orders");
    let locked = format!("-c search_path=sales {LOCK}");
    let expected =
        startup_wire(PROTOCOL_3_0, &[("user", IAM_USER), ("database", "orders"), ("application_name", "psql"), ("options", locked.as_str())]);
    assert_eq!(upstream.received(), vec![expected], "the bytes Cloud SQL got");
    // An app that sends no options gets the lock as an option of its own.
    let mut bare = App::connect(port);
    bare.startup(&[("user", "frank"), ("database", "orders")]);
    bare.sign_in(PASSWORD);
    assert_eq!(upstream.received()[1], startup_wire(PROTOCOL_3_0, &[("user", IAM_USER), ("database", "orders"), ("options", LOCK)]));
}

#[test]
fn dev_and_staging_sessions_are_not_locked() {
    for environment in [DatabaseEnvironment::Dev, DatabaseEnvironment::Staging] {
        let upstream = fake();
        let ports = DatabasePorts::new(upstream.clone());
        let db = SavedDatabase { environment, project: "acme-dev-654321".into(), ..orders() };
        let port = running(&ports, &db);
        let mut app = App::connect(port);
        app.startup(&[("user", "frank"), ("database", "orders"), ("options", "-c search_path=sales")]);
        app.sign_in(PASSWORD);
        let expected = startup_wire(PROTOCOL_3_0, &[("user", IAM_USER), ("database", "orders"), ("options", "-c search_path=sales")]);
        assert_eq!(upstream.received(), vec![expected], "{environment:?}");
    }
}

#[test]
fn ssl_and_gss_requests_are_refused_and_the_startup_continues() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    // libpq with gssencmode=prefer and sslmode=prefer asks for both, in this order.
    let mut app = App::connect(port);
    app.send(&request(GSSENC_REQUEST));
    assert_eq!(app.bytes(1), b"N");
    app.send(&request(SSL_REQUEST));
    assert_eq!(app.bytes(1), b"N");
    app.startup(&[("user", "frank"), ("database", "orders")]);
    app.sign_in(PASSWORD);
    app.round_trip(b"select 1");
    // An app that asks a third time is not served.
    let mut pushy = App::connect(port);
    for code in [SSL_REQUEST, SSL_REQUEST] {
        pushy.send(&request(code));
        assert_eq!(pushy.bytes(1), b"N");
    }
    pushy.send(&request(SSL_REQUEST));
    assert_eq!(pushy.error().0, "08P01");
    assert!(pushy.closed());
    assert_eq!(upstream.prepared.load(Ordering::SeqCst), 1, "only the app that went on was prepared for");
}

#[test]
fn a_newer_protocol_is_negotiated_before_the_password() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut app = App::connect(port);
    app.send(&startup_wire(PROTOCOL_3_2, &[("user", "frank"), ("database", "orders"), ("_pq_.compression", "on")]));
    // NegotiateProtocolVersion first, as a server of protocol 3.0 sends it: the version it speaks and the option it does not know.
    let mut negotiation = PROTOCOL_3_0.to_be_bytes().to_vec();
    negotiation.extend_from_slice(&1u32.to_be_bytes());
    negotiation.extend_from_slice(b"_pq_.compression\0");
    assert_eq!(app.message(), (b'v', negotiation));
    app.sign_in(PASSWORD);
    let expected = startup_wire(PROTOCOL_3_0, &[("user", IAM_USER), ("database", "orders"), ("options", LOCK)]);
    assert_eq!(upstream.received(), vec![expected], "Cloud SQL gets protocol 3.0 and no protocol option");
}

#[test]
fn a_password_request_from_cloud_sql_becomes_a_clear_error() {
    let upstream = fake();
    *upstream.answer.lock().unwrap() = Answer::AsksForPassword;
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut app = App::connect(port);
    app.startup(&[("user", "frank"), ("database", "orders")]);
    app.asked_for_password();
    app.password(PASSWORD);
    let sentence = format!("Cloud SQL asked for a database password. Turn on IAM database authentication for {CONNECTION}.");
    assert_eq!(app.error(), ("28000".to_string(), sentence));
    assert!(app.closed());
    assert_eq!(upstream.forgotten.load(Ordering::SeqCst), 0, "the certificate was fine");
}

#[test]
fn a_failed_prepare_is_refused_with_its_sentence() {
    let upstream = fake();
    *upstream.refusing.lock().unwrap() = Some(EXPIRED.into());
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut app = App::connect(port);
    app.startup(&[("user", "frank"), ("database", "orders")]);
    app.asked_for_password();
    app.password(PASSWORD);
    assert_eq!(app.error(), ("28000".to_string(), EXPIRED.to_string()));
    assert!(app.closed());
    assert_eq!(upstream.dialled.load(Ordering::SeqCst), 0);
}

#[test]
fn a_failure_reaching_cloud_sql_drops_the_cached_certificate() {
    let upstream = fake();
    *upstream.answer.lock().unwrap() = Answer::HangsUp;
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let refused = |app: &mut App, reason: &str| {
        app.startup(&[("user", "frank"), ("database", "orders")]);
        app.asked_for_password();
        app.password(PASSWORD);
        assert_eq!(app.error(), ("08006".to_string(), format!("Lunport could not reach {CONNECTION}: {reason}")));
        assert!(app.closed());
    };
    // Cloud SQL closes the TLS connection on the first read, as it does when it refuses the certificate.
    refused(&mut App::connect(port), "Cloud SQL closed the connection.");
    assert_eq!(upstream.forgotten.load(Ordering::SeqCst), 1, "the next connection fetches a new certificate");
    // Cloud SQL cannot be dialled at all.
    upstream.unreachable.store(true, Ordering::SeqCst);
    refused(&mut App::connect(port), "Cloud SQL refused the connection.");
    assert_eq!(upstream.forgotten.load(Ordering::SeqCst), 2);
}

#[test]
fn a_startup_too_long_for_cloud_sql_is_refused_with_a_sentence() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    // The start-up message Cloud SQL would get with `name` as the application's name: at most 10,000 bytes after its length word.
    let rewritten = |name: &str| startup_wire(PROTOCOL_3_0, &[("user", IAM_USER), ("database", "orders"), ("application_name", name), ("options", LOCK)]).len();
    let fits = "a".repeat(10_004 - rewritten(""));
    assert_eq!(rewritten(&fits), 10_004);
    let mut app = App::connect(port);
    app.startup(&[("user", "frank"), ("database", "orders"), ("application_name", fits.as_str())]);
    app.sign_in(PASSWORD);
    assert_eq!(upstream.dialled.load(Ordering::SeqCst), 1);
    let too_long = format!("{fits}a");
    let mut long = App::connect(port);
    long.startup(&[("user", "frank"), ("database", "orders"), ("application_name", too_long.as_str())]);
    long.asked_for_password();
    long.password(PASSWORD);
    let sentence = "The connection settings are too long for Cloud SQL. Remove some options and connect again.";
    assert_eq!(long.error(), ("08P01".to_string(), sentence.to_string()));
    assert!(long.closed());
    assert_eq!(upstream.dialled.load(Ordering::SeqCst), 1, "nothing was sent to Cloud SQL");
}

#[test]
fn a_cancel_request_is_passed_on_as_it_is() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut app = App::connect(port);
    app.send(&cancel_request());
    assert!(app.closed(), "the port hangs up once Cloud SQL took the request");
    assert_eq!(upstream.received(), vec![cancel_request()]);
    assert_eq!(upstream.prepared.load(Ordering::SeqCst), 0, "a cancel request carries no password and needs no preparing");
}

#[test]
fn an_app_that_does_not_sign_in_in_time_is_closed() {
    let upstream = fake();
    let limit = Duration::from_secs(1);
    let ports = DatabasePorts::new(upstream.clone()).signing_in_within(limit);
    let port = running(&ports, &orders());
    let started = Instant::now();
    let mut silent = App::connect(port);
    let mut no_password = App::connect(port);
    no_password.startup(&[("user", "frank"), ("database", "orders")]);
    no_password.asked_for_password();
    assert!(silent.closed(), "an app that sends nothing");
    assert!(no_password.closed(), "an app that never gives the password");
    assert!(started.elapsed() >= limit, "closed at the limit, not before");
    wait_until("their slots are free", || ports.live(ID).connections == 0);
    assert_eq!(upstream.prepared.load(Ordering::SeqCst), 0);
    // The limit ends once the password was checked: a session then lasts as long as the app likes.
    let mut session = App::signed_in(port);
    std::thread::sleep(limit + Duration::from_millis(500));
    session.round_trip(b"select 1");
}

// ---- Starting and stopping ----

#[test]
fn a_port_in_use_fails_with_a_sentence() {
    let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let taken = held.local_addr().unwrap().port();
    let ports = DatabasePorts::new(fake());
    let db = SavedDatabase { local_port: Some(taken), ..orders() };
    let sentence = format!("Port {taken} is already in use on this computer.");
    let started = ports.start(&db, Zeroizing::new(PASSWORD.into()), CancelToken::default(), Box::new(()));
    assert_eq!(started, Err(sentence.clone()));
    assert_eq!(ports.live(ID), DatabaseLive { phase: DatabasePhase::Error, port: None, connections: 0, writable_until_ms: None, error: Some(sentence) });
    assert!(!ports.running(ID));
    assert!(locked(&ports.ports)[ID].password().is_empty(), "a port that failed keeps no password");
    // Nothing else breaks: another database starts, and this one does once the port is free.
    let other = SavedDatabase { id: OTHER.into(), ..orders() };
    App::signed_in(running(&ports, &other)).round_trip(b"select 1");
    drop(held);
    assert_eq!(running(&ports, &db), taken);
    App::signed_in(taken).round_trip(b"select 1");
}

/// Starts `Orders` on the port `occupant` listens on, and expects it to fail as a port in use.
fn refused_for(occupant: std::net::TcpListener) {
    let taken = occupant.local_addr().unwrap().port();
    let ports = DatabasePorts::new(fake());
    let db = SavedDatabase { local_port: Some(taken), ..orders() };
    let sentence = format!("Port {taken} is already in use on this computer.");
    assert_eq!(ports.start(&db, Zeroizing::new(PASSWORD.into()), CancelToken::default(), Box::new(())), Err(sentence.clone()));
    assert_eq!((ports.live(ID).phase, ports.live(ID).error), (DatabasePhase::Error, Some(sentence)));
    drop(occupant);
}

#[test]
fn a_program_listening_on_every_address_holds_the_port() {
    // As Docker's `-p 5432:5432` listens: on 0.0.0.0, which does not make a bind to 127.0.0.1 fail on macOS.
    refused_for(std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap());
}

#[test]
fn a_program_listening_on_the_ipv6_loopback_holds_the_port() {
    // Apps that dial `localhost` may try ::1 first. A computer without IPv6 has nothing to try here.
    let Ok(occupant) = std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)) else { return };
    refused_for(occupant);
}

#[test]
fn a_database_without_a_local_port_or_over_the_limit_does_not_start() {
    let ports = DatabasePorts::new(fake());
    let unshared = SavedDatabase { local_port: None, ..orders() };
    let start = |db: &SavedDatabase| ports.start(db, Zeroizing::new(PASSWORD.into()), CancelToken::default(), Box::new(()));
    assert_eq!(start(&unshared), Err("Turn on Let other apps connect and choose a port first.".to_string()));
    assert_eq!(ports.live(ID), DatabaseLive::default(), "nothing was started");
    let ids: Vec<String> = (1..=MAX_RUNNING_DATABASES + 1).map(|n| format!("{n:016x}")).collect();
    for id in &ids[..MAX_RUNNING_DATABASES] {
        running(&ports, &SavedDatabase { id: id.clone(), ..orders() });
    }
    let seventeenth = SavedDatabase { id: ids[MAX_RUNNING_DATABASES].clone(), ..orders() };
    assert_eq!(start(&seventeenth), Err("Lunport runs up to 16 databases at once.".to_string()));
    assert!(!ports.running(&seventeenth.id));
    // A database that runs already is not started twice.
    assert_eq!(start(&SavedDatabase { id: ids[0].clone(), ..orders() }), Err("Orders is already running.".to_string()));
    // One stopped makes room.
    ports.stop(&ids[0]);
    wait_until("the first stopped", || ports.live(&ids[0]).phase == DatabasePhase::Stopped);
    running(&ports, &seventeenth);
}

#[test]
fn the_65th_connection_is_refused_with_53300() {
    let ports = DatabasePorts::new(fake());
    let port = running(&ports, &orders());
    let mut apps: Vec<App> = (0..MAX_PORT_CONNECTIONS).map(|_| App::connect(port)).collect();
    wait_until("64 connections are open", || ports.live(ID).connections == 64);
    let mut extra = App::connect(port);
    extra.send(&request(SSL_REQUEST));
    assert_eq!(extra.bytes(1), b"N", "it is answered as any app is");
    extra.startup(&[("user", "frank"), ("database", "orders")]);
    assert_eq!(extra.error(), ("53300".to_string(), "Orders has reached 64 connections.".to_string()));
    assert!(extra.closed());
    assert_eq!(ports.live(ID).connections, 64);
    // The connections that were let in sign in as ever.
    apps[0].startup(&[("user", "frank"), ("database", "orders")]);
    apps[0].sign_in(PASSWORD);
    apps[0].round_trip(b"select 1");
    // One that closes makes room for another.
    drop(apps.pop());
    wait_until("a slot is free", || ports.live(ID).connections == 63);
    App::signed_in(port).round_trip(b"select 1");
}

#[test]
fn a_cancel_request_on_a_full_port_is_closed_without_dialling() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let _apps: Vec<App> = (0..MAX_PORT_CONNECTIONS).map(|_| App::connect(port)).collect();
    wait_until("64 connections are open", || ports.live(ID).connections == 64);
    let mut cancel = App::connect(port);
    cancel.send(&cancel_request());
    assert!(cancel.closed());
    assert_eq!(upstream.dialled.load(Ordering::SeqCst), 0, "Cloud SQL was not dialled");
    assert!(upstream.received().is_empty());
}

#[test]
fn open_connections_survive_a_failed_refresh() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut open = App::signed_in(port);
    open.round_trip(b"begin");
    // The gcloud sign-in expires: a new connection cannot get a certificate.
    *upstream.refusing.lock().unwrap() = Some(EXPIRED.into());
    let mut new = App::connect(port);
    new.startup(&[("user", "frank"), ("database", "orders")]);
    new.asked_for_password();
    new.password(PASSWORD);
    assert_eq!(new.error(), ("28000".to_string(), EXPIRED.to_string()));
    // The open one goes on as before.
    open.round_trip(b"select * from orders where unpaid");
    open.round_trip(b"commit");
    wait_until("only the open connection is left", || ports.live(ID).connections == 1);
}

#[test]
fn stopping_closes_every_connection_and_frees_the_port() {
    let upstream = fake();
    let ports = DatabasePorts::new(upstream.clone());
    let port = running(&ports, &orders());
    let mut relaying = App::signed_in(port);
    let mut silent = App::connect(port);
    // A connection whose preparing waits for the person (a grant question) when the port stops.
    upstream.waiting.store(true, Ordering::SeqCst);
    let mut asking = App::connect(port);
    asking.startup(&[("user", "frank"), ("database", "orders")]);
    asking.asked_for_password();
    asking.password(PASSWORD);
    wait_until("the third connection is being prepared", || upstream.prepared.load(Ordering::SeqCst) == 2);
    assert_eq!(ports.live(ID).connections, 3);
    ports.stop(ID);
    wait_until("the port stopped", || ports.live(ID).phase == DatabasePhase::Stopped);
    assert!(relaying.closed(), "a session in progress");
    assert!(silent.closed(), "an app that had not signed in");
    // Its preparing gives up when the port stops, and it may be refused for that before its connection is closed.
    assert!(asking.ended(), "an app waiting for its connection to be prepared");
    wait_until("the preparing was cancelled with the port", || upstream.cancelled.load(Ordering::SeqCst) == 1);
    assert_eq!(ports.live(ID), DatabaseLive::default());
    assert!(!ports.running(ID));
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port)).expect("the port is free again");
}

#[test]
fn quitting_stops_the_port_and_lets_go_of_what_it_held() {
    struct Held(Arc<AtomicBool>);
    impl Drop for Held {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let ports = DatabasePorts::new(fake());
    let quit = CancelToken::default();
    let released = Arc::new(AtomicBool::new(false));
    ports.start(&orders(), Zeroizing::new(PASSWORD.into()), quit.clone(), Box::new(Held(Arc::clone(&released)))).unwrap();
    let mut relaying = App::signed_in(ports.live(ID).port.unwrap());
    assert!(!released.load(Ordering::SeqCst), "held while the port runs");
    // The broker cancels the token when the app quits.
    quit.cancel();
    wait_until("the port stopped", || ports.live(ID).phase == DatabasePhase::Stopped);
    assert!(relaying.closed());
    wait_until("what the port held was let go", || released.load(Ordering::SeqCst));
}

#[test]
fn edits_are_refused_while_the_database_runs() {
    let ports = DatabasePorts::new(fake());
    let saved = AtomicUsize::new(0);
    let save = || {
        saved.fetch_add(1, Ordering::SeqCst);
        Ok("saved")
    };
    assert_eq!(ports.edit(ID, save), Ok("saved"), "a database that does not run is changed");
    running(&ports, &orders());
    assert_eq!(ports.edit(ID, save), Err("Stop Orders before you change it.".to_string()));
    assert_eq!(saved.load(Ordering::SeqCst), 1, "nothing was saved");
    assert_eq!(ports.edit(OTHER, save), Ok("saved"), "another database is changed meanwhile");
    ports.stop(ID);
    wait_until("the port stopped", || ports.live(ID).phase == DatabasePhase::Stopped);
    assert_eq!(ports.edit(ID, save), Ok("saved"));
    assert_eq!(saved.load(Ordering::SeqCst), 3);
}

#[test]
fn a_new_password_is_asked_of_new_connections_only() {
    let ports = DatabasePorts::new(fake());
    let port = running(&ports, &orders());
    let mut open = App::signed_in(port);
    let rotated = "bmV3LXBvcnQtcGFzc3dvcmQtZm9yLWFu";
    ports.set_password(ID, Zeroizing::new(rotated.into()));
    let mut old = App::connect(port);
    old.startup(&[("user", "frank"), ("database", "orders")]);
    old.asked_for_password();
    old.password(PASSWORD);
    assert_eq!(old.error().0, "28P01");
    let mut new = App::connect(port);
    new.startup(&[("user", "frank"), ("database", "orders")]);
    new.sign_in(rotated);
    open.round_trip(b"select 1");
}

#[test]
fn a_stopped_port_is_not_given_a_password() {
    let ports = DatabasePorts::new(fake());
    let rotated = "bmV3LXBvcnQtcGFzc3dvcmQtZm9yLWFu";
    // A database that never ran has no port to give one to.
    ports.set_password(ID, Zeroizing::new(rotated.into()));
    assert_eq!(ports.live(ID), DatabaseLive::default());
    running(&ports, &orders());
    ports.stop(ID);
    wait_until("the port stopped", || ports.live(ID).phase == DatabasePhase::Stopped);
    assert!(locked(&ports.ports)[ID].password().is_empty(), "the stopped port keeps no password");
    ports.set_password(ID, Zeroizing::new(rotated.into()));
    assert!(locked(&ports.ports)[ID].password().is_empty(), "and is not given one");
    // It asks for the password it is started with next.
    ports.start(&orders(), Zeroizing::new(rotated.into()), CancelToken::default(), Box::new(())).unwrap();
    let port = ports.live(ID).port.unwrap();
    let mut old = App::connect(port);
    old.startup(&[("user", "frank"), ("database", "orders")]);
    old.asked_for_password();
    old.password(PASSWORD);
    assert_eq!(old.error().0, "28P01");
    let mut new = App::connect(port);
    new.startup(&[("user", "frank"), ("database", "orders")]);
    new.sign_in(rotated);
}

#[test]
fn a_failed_port_is_not_given_a_password() {
    let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let db = SavedDatabase { local_port: Some(held.local_addr().unwrap().port()), ..orders() };
    let ports = DatabasePorts::new(fake());
    ports.start(&db, Zeroizing::new(PASSWORD.into()), CancelToken::default(), Box::new(())).unwrap_err();
    assert_eq!(ports.live(ID).phase, DatabasePhase::Error);
    ports.set_password(ID, Zeroizing::new("bmV3LXBvcnQtcGFzc3dvcmQtZm9yLWFu".into()));
    assert!(locked(&ports.ports)[ID].password().is_empty(), "a port that failed is not given a password");
}

#[test]
fn a_port_takes_a_new_password_while_it_starts_or_runs_only() {
    let port = Port::new(orders(), Zeroizing::new(PASSWORD.into()), CancelToken::default());
    assert_eq!(port.live().phase, DatabasePhase::Starting);
    port.set_password(Zeroizing::new("first".into()));
    assert_eq!(*port.password(), "first", "a port that starts takes it");
    port.listening(6543);
    port.set_password(Zeroizing::new("second".into()));
    assert_eq!(*port.password(), "second", "a port that runs takes it");
    // A port that stops wipes its password once its connections are closed: a password it took meanwhile could be written after the wipe.
    port.stop();
    assert_eq!(port.live().phase, DatabasePhase::Stopping);
    port.set_password(Zeroizing::new("third".into()));
    assert_eq!(*port.password(), "second", "a port that stops does not");
    port.forget_password();
    port.stopped();
    port.set_password(Zeroizing::new("fourth".into()));
    assert!(port.password().is_empty(), "nor does one that stopped");
}

// ---- Port passwords ----

#[test]
fn a_password_is_created_once_and_reused() {
    let keychain = MemKeychain::default();
    let first = ensure_password(&keychain, ID).unwrap();
    assert_eq!(keychain.entry("database:port-password:00000000000000d1").as_deref(), Some(first.as_str()), "stored before it is used");
    assert_eq!(*ensure_password(&keychain, ID).unwrap(), *first, "the stored one is used again");
    let other = ensure_password(&keychain, OTHER).unwrap();
    assert_ne!(*other, *first, "every database has a password of its own");
    assert_eq!(keychain.entry(&password_account(OTHER)).as_deref(), Some(other.as_str()));
}

#[test]
fn passwords_are_32_url_safe_characters() {
    for _ in 0..32 {
        let password = ensure_password(&MemKeychain::default(), ID).unwrap();
        assert_eq!(password.len(), 32, "{}", password.len());
        assert!(password.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'), "URL-safe base64 without padding");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(password.as_bytes()).unwrap();
        assert_eq!(decoded.len(), 24, "24 random bytes");
    }
}

// ---- A clock of the tests' own ----

/// A moment the tests share: 2027-01-15T08:00:00Z.
pub(crate) fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
}

/// The test's own clock, which only the test moves.
#[derive(Clone)]
pub(crate) struct Clock(Arc<Mutex<SystemTime>>);

impl Clock {
    pub(crate) fn new() -> Clock {
        Clock(Arc::new(Mutex::new(t0())))
    }

    pub(crate) fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }

    /// Moves the clock to `elapsed` after `t0`.
    pub(crate) fn at(&self, elapsed: Duration) {
        *self.0.lock().unwrap() = t0() + elapsed;
    }
}
