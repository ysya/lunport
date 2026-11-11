//! The local port of a saved database: Lunport listens on 127.0.0.1 for the apps on this computer (DataGrip, psql) and signs them in to
//! Cloud SQL with the person's Google account. An app signs in to the port with the password Lunport made for the database. Lunport then
//! gets what the connection needs from Google (the Privileged Access Manager grant the database asks for, and a client certificate Cloud
//! SQL signs), dials the instance over TLS, passes the app's start-up message on as the IAM database user, with Cloud SQL's read-only lock
//! for a prod database, and relays the session.
//!
//! The lock stays with a session for as long as it lasts. Once the person unlocks writes, for `WRITABLE_WINDOW`, the new connections to a
//! prod database come without it; the locked ones go on until their apps connect again. When the window ends, the connections that came
//! without the lock close as soon as they are idle, and `CLOSE_UNLOCKED_WITHIN` after the window at the latest. A port runs the database
//! as it was saved when the port started, but locks as prod whenever either that database or the one saved now is prod
//! (`effective_environment`): another device that makes a running database prod locks its next connections at once, and one that makes it
//! dev leaves it locked until it is started again.
//!
//! The ports run on one small runtime of their own. What blocks (Google's APIs, a grant question that waits for the person) runs on its
//! blocking threads. Each port is registered with the broker while it runs, so quitting the app stops it.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use futures_util::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use zeroize::Zeroizing;

use super::auth::{label, printable};
use super::connect::CancelToken;
use super::databases::{DatabaseLive, DatabasePhase};
use super::pgwire::{auth_cleartext, error_response, passwords_match, read_first, read_password, read_server_auth, FirstMessage, ReadyTracker, ServerAuth, Startup};
use crate::sync::databases::{DatabaseEnvironment, SavedDatabase};
use crate::sync::env::Keychain;

/// The most connections one port has open at once.
pub const MAX_PORT_CONNECTIONS: usize = 64;
/// The most databases that run at once on this device.
pub const MAX_RUNNING_DATABASES: usize = 16;
/// The soft limit of open files the app raises itself to as it starts (`raise_open_file_limit`): room for `MAX_RUNNING_DATABASES` ports
/// of `MAX_PORT_CONNECTIONS` connections, each holding two sockets (the app's and Cloud SQL's), beside everything else the app keeps open.
/// It is `OPEN_MAX` on macOS, the most a process may ask for there.
#[cfg(any(unix, test))]
const OPEN_FILES: u64 = 10_240;
/// How long a prod database takes writes through its port once the person unlocks them.
pub const WRITABLE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// How long after its writable window ended a connection that came without the lock is closed at the latest, idle or not: a transaction
/// it still has open is rolled back.
pub const CLOSE_UNLOCKED_WITHIN: Duration = Duration::from_secs(10 * 60);

/// What a database without a local port is refused with when it is started.
pub(crate) const NO_LOCAL_PORT: &str = "Turn on Let other apps connect and choose a port first.";
/// How long an app has, from when it connects, to send its start-up message and the password: a connection that sends nothing would
/// otherwise hold one of the port's slots for good.
const SIGN_IN_WITHIN: Duration = Duration::from_secs(30);
/// How many requests for encryption (SSLRequest, GSSENCRequest) an app is answered `N` to: libpq asks for both, one after the other.
const MAX_ENCRYPTION_REQUESTS: usize = 2;
/// The most bytes Cloud SQL takes in a start-up message after its length word: it closes the connection without a word on a longer one.
const MAX_CLOUD_SQL_STARTUP_BYTES: usize = 10_000;
/// How long Cloud SQL has to answer the start-up message.
const SERVER_ANSWER_WITHIN: Duration = Duration::from_secs(30);
/// How often a port looks whether the app is quitting (the broker cancels its token).
const QUIT_POLL: Duration = Duration::from_millis(250);
/// How long a port waits after a connection it could not take before it takes the next one.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// How long a cancel request may take to reach Cloud SQL and be taken.
const CANCEL_WITHIN: Duration = Duration::from_secs(10);
/// How long a look at whether a program already answers on a port may take, for each loopback address.
const PROBE_WITHIN: Duration = Duration::from_millis(300);
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
/// How many random bytes a port's password is made of.
const PASSWORD_BYTES: usize = 24;
/// The most characters of an error sentence, as a tunnel's.
const ERROR_CHARS: usize = 512;
const TOO_LONG: &str = "The connection settings are too long for Cloud SQL. Remove some options and connect again.";
const UNAVAILABLE: &str = "Lunport's database service is unavailable. Restart Lunport and try again.";
const ONLY_PROD: &str = "Only prod databases are locked.";
const NOT_RUNNING: &str = "Start the database before you unlock writes.";
/// What an unlock is refused with when the person did not confirm it, or confirmed it for a run of the database that has ended.
pub(crate) const STAY_LOCKED: &str = "Writes stay locked.";
/// How often a port looks whether its writable window ended and whether a connection that came without the lock is past its time.
const TICK: Duration = Duration::from_secs(1);

/// The clocks of the ports: the wall clock, which the page shows and which goes on while the computer sleeps, and a monotonic clock, which
/// no change of the wall clock moves.
#[derive(Clone)]
pub(crate) struct Clocks {
    wall: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    monotonic: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl Default for Clocks {
    fn default() -> Self {
        Clocks { wall: Arc::new(SystemTime::now), monotonic: Arc::new(Instant::now) }
    }
}

impl Clocks {
    /// Clocks that the tests move themselves.
    #[cfg(test)]
    pub(crate) fn new(wall: impl Fn() -> SystemTime + Send + Sync + 'static, monotonic: impl Fn() -> Instant + Send + Sync + 'static) -> Clocks {
        Clocks { wall: Arc::new(wall), monotonic: Arc::new(monotonic) }
    }

    /// Now, by both clocks.
    fn now(&self) -> Moment {
        Moment { wall: (self.wall)(), monotonic: (self.monotonic)() }
    }
}

/// A moment by both clocks. A writable window, and the time a connection that came without the lock has after it, end when either clock
/// reaches their end: a wall clock that is set back does not stretch them, and a computer that slept through them ends them as it wakes.
#[derive(Clone, Copy)]
struct Moment {
    wall: SystemTime,
    monotonic: Instant,
}

impl Moment {
    /// `span` after this moment, by both clocks.
    fn after(self, span: Duration) -> Moment {
        Moment { wall: self.wall + span, monotonic: self.monotonic + span }
    }

    /// Whether `now` has reached this moment, by either clock.
    fn reached_by(self, now: Moment) -> bool {
        now.wall >= self.wall || now.monotonic >= self.monotonic
    }

    /// The earlier of this moment and `other`, by each clock.
    fn earlier(self, other: Moment) -> Moment {
        Moment { wall: self.wall.min(other.wall), monotonic: self.monotonic.min(other.monotonic) }
    }

    /// When this moment comes by the wall clock as it reads at `now`: at its wall time, or sooner where the monotonic clock gets there
    /// first.
    fn on_the_wall(self, now: Moment) -> SystemTime {
        self.wall.min(now.wall + self.monotonic.saturating_duration_since(now.monotonic))
    }
}

/// A byte stream both ways: the connection to Cloud SQL as the port relays it.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
pub type BoxStream = Box<dyn Duplex>;

/// Where a port's connections reach Cloud SQL from.
pub(crate) trait Upstream: Send + Sync {
    /// Gets what a connection to `db` needs (the grant it asks for, the connection material) and answers the database user the connection
    /// signs in as with the material it got; an error is what the app is refused with. It blocks (Google's APIs, a question that waits for
    /// the person), so the port calls it on a blocking thread. `cancel` is set when the port stops.
    fn prepare(&self, db: &SavedDatabase, cancel: &CancelToken) -> Result<Prepared, NotReady>;
    /// Dials the instance of the database `db_id` with the material numbered `material`, the one `prepare` got for the connection, and
    /// with none when that material is gone: the user it signs in as goes with that material's certificate. A cancel request, which signs
    /// in as nobody, passes `None` and dials with the material the database's connections have now.
    fn connect(&self, db_id: &str, material: Option<u64>) -> Dialling;
    /// A connection to `db_id` dialled with `material` failed before Cloud SQL answered its start-up message (in TLS 1.3 a refused client
    /// certificate shows only then): that material is not used again, and the next connection gets new material. Newer material that
    /// another connection got meanwhile stays.
    fn forget(&self, db_id: &str, material: u64);
    /// The database `db_id` stopped, or was deleted: everything kept for it goes, its certificate and the key that was made for it too.
    fn release(&self, db_id: &str);
}

/// Why a connection could not be got ready (`Upstream::prepare`): the sentence the app is refused with, under the SQLSTATE of its kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NotReady {
    /// The sign-in or the grant was refused: a Google sign-in that expired, an account that may not connect, a grant that is missing or
    /// was declined. The app is told `28000` (invalid_authorization_specification).
    Refused(String),
    /// Google or the instance could not be reached or used: the network, the Cloud SQL Admin API (not enabled, no such instance, an
    /// answer it could not read), an instance Lunport does not connect to (no public IP, not PostgreSQL, in another region). The app is
    /// told `08006` (connection_failure).
    Failed(String),
}

impl NotReady {
    /// The SQLSTATE the app is refused with.
    pub(crate) fn sqlstate(&self) -> &'static str {
        match self {
            NotReady::Refused(_) => "28000",
            NotReady::Failed(_) => "08006",
        }
    }

    /// The sentence the app is refused with.
    pub(crate) fn sentence(&self) -> &str {
        match self {
            NotReady::Refused(sentence) | NotReady::Failed(sentence) => sentence,
        }
    }
}

/// What a connection to a database got ready with.
pub(crate) struct Prepared {
    /// The database user it signs in as.
    pub iam_user: String,
    /// Which of the database's material it dials with (`Upstream::connect`).
    pub material: u64,
}

/// A connection to an instance under way.
pub(crate) struct Dialling {
    /// Which of the database's material it dials with, for `Upstream::forget`; `None` when there was none to dial with.
    pub material: Option<u64>,
    pub stream: BoxFuture<'static, io::Result<BoxStream>>,
}

/// Reads the saved database `id` as the library holds it now: `None` once it is gone, and the sentence of why when the library cannot be
/// read. It blocks on the library, so the ports call it on a blocking thread.
pub(crate) type ReadSaved = Arc<dyn Fn(&str) -> Result<Option<SavedDatabase>, String> + Send + Sync>;

/// The environment a database is shown in and its port locks by: prod when `saved`, the database as it is saved now, is prod, or when it
/// runs and `running`, the database its port started with, is; the saved one's otherwise. A port runs the database it started with, so a
/// change another device makes to it waits for the next start, but the lock does not wait.
pub(crate) fn effective_environment(saved: &SavedDatabase, running: Option<&SavedDatabase>) -> DatabaseEnvironment {
    if saved.is_prod() || running.is_some_and(SavedDatabase::is_prod) {
        DatabaseEnvironment::Prod
    } else {
        saved.environment
    }
}

/// The soft open-file limit to raise to from `soft`: the lower of `OPEN_FILES`, the hard limit `hard` and, where the system has one, its
/// limit for one process (`per_process`). `None` when `soft` is that high already, so that the limit is never lowered.
#[cfg(any(unix, test))]
fn open_file_target(soft: u64, hard: u64, per_process: Option<u64>) -> Option<u64> {
    let target = OPEN_FILES.min(hard).min(per_process.unwrap_or(u64::MAX));
    (target > soft).then_some(target)
}

/// Raises this process's soft open-file limit (`RLIMIT_NOFILE`) to `open_file_target` as the app starts: a Mac starts an app with 256,
/// fewer than the database ports may hold. A limit that cannot be read or raised is written to the log and changes nothing else.
#[cfg(unix)]
pub(crate) fn raise_open_file_limit() {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit only writes the limits into `limit`, which outlives the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        eprintln!("[databases] could not read the open-file limit: {}", io::Error::last_os_error());
        return;
    }
    let (soft, hard) = (u64::from(limit.rlim_cur), u64::from(limit.rlim_max));
    let Some(target) = open_file_target(soft, hard, max_files_per_process()) else { return };
    let raised = libc::rlimit { rlim_cur: target, rlim_max: limit.rlim_max };
    // SAFETY: setrlimit only reads `raised`, which outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        eprintln!("[databases] could not raise the open-file limit from {soft} to {target}: {}", io::Error::last_os_error());
    }
}

/// The most files one process may open on this Mac (`kern.maxfilesperproc`): macOS refuses a soft limit above it, as it refuses an
/// unlimited one.
#[cfg(target_os = "macos")]
fn max_files_per_process() -> Option<u64> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    // SAFETY: the name ends with a zero byte; sysctlbyname writes at most `size` bytes into `value`, and how many it wrote into `size`.
    let read = unsafe { libc::sysctlbyname(c"kern.maxfilesperproc".as_ptr(), (&raw mut value).cast(), &mut size, std::ptr::null_mut(), 0) };
    (read == 0 && size == std::mem::size_of::<libc::c_int>()).then(|| u64::try_from(value).ok()).flatten().filter(|&value| value > 0)
}

/// Linux has no limit for one process beside the hard limit.
#[cfg(all(unix, not(target_os = "macos")))]
fn max_files_per_process() -> Option<u64> {
    None
}

// ---- Passwords ----

/// The keychain account that holds the password of the database `id`'s port.
pub(crate) fn password_account(id: &str) -> String {
    format!("database:port-password:{id}")
}

/// The password of the database `id`'s port: the one `keychain` holds, else a new one, stored before it is answered.
pub(crate) fn ensure_password(keychain: &dyn Keychain, id: &str) -> Result<Zeroizing<String>, String> {
    let stored = keychain.get(&password_account(id)).map_err(|error| format!("The database's password could not be read from the keychain: {error}"))?;
    match stored.filter(|stored| !stored.is_empty()) {
        Some(stored) => Ok(Zeroizing::new(stored)),
        None => replace_password(keychain, id),
    }
}

/// Makes a new password for the database `id`'s port and stores it in `keychain` in place of the one held, before it is answered: when
/// the keychain cannot keep it, the caller still has the old one. A new password is `PASSWORD_BYTES` random bytes as URL-safe base64
/// without padding, 32 characters an app takes as they are, in a connection URL too.
pub(crate) fn replace_password(keychain: &dyn Keychain, id: &str) -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new([0u8; PASSWORD_BYTES]);
    getrandom::fill(&mut bytes[..]).map_err(|_| "Could not make a password for the database.".to_string())?;
    let password = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[..]));
    keychain.set(&password_account(id), &password).map_err(|error| format!("The database's password could not be saved in the keychain: {error}"))?;
    Ok(password)
}

// ---- The ports ----

/// The local ports of the saved databases this device runs.
pub(crate) struct DatabasePorts {
    upstream: OnceLock<Arc<dyn Upstream>>,
    /// Reads the saved databases as the library holds them now (the app's ports get it with `use_library`). Without it the database a
    /// port started with decides alone.
    saved: OnceLock<ReadSaved>,
    /// Made when the first port starts; `None` when it could not be made.
    runtime: OnceLock<Option<PortRuntime>>,
    /// Held by an edit of a saved database, and by a start while it reads the database it starts: the two do not interleave.
    edits: Mutex<()>,
    ports: Mutex<BTreeMap<String, Arc<Port>>>,
    sign_in_within: Duration,
    clocks: Clocks,
    tick: Duration,
}

impl Default for DatabasePorts {
    fn default() -> Self {
        DatabasePorts {
            upstream: OnceLock::new(),
            saved: OnceLock::new(),
            runtime: OnceLock::new(),
            edits: Mutex::new(()),
            ports: Mutex::default(),
            sign_in_within: SIGN_IN_WITHIN,
            clocks: Clocks::default(),
            tick: TICK,
        }
    }
}

/// The runtime the ports run on: two workers, named as the app's threads are. Dropping it does not wait for the ports.
struct PortRuntime(Option<tokio::runtime::Runtime>);

impl PortRuntime {
    fn new() -> Option<PortRuntime> {
        let runtime =
            tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name(crate::identity::thread_name("database")).enable_all().build().ok()?;
        Some(PortRuntime(Some(runtime)))
    }

    fn get(&self) -> &tokio::runtime::Runtime {
        self.0.as_ref().expect("the runtime is taken only when it is dropped")
    }
}

impl Drop for PortRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

impl DatabasePorts {
    /// The ports over `upstream` (the app's ports get theirs with `use_upstream`, once the broker is there).
    #[cfg(test)]
    pub fn new(upstream: Arc<dyn Upstream>) -> Self {
        let ports = DatabasePorts::default();
        let _ = ports.upstream.set(upstream);
        ports
    }

    /// Has the ports reach Cloud SQL through `make()`'s upstream, made the first time this is called; later calls keep that one.
    pub(crate) fn use_upstream(&self, make: impl FnOnce() -> Arc<dyn Upstream>) {
        self.upstream.get_or_init(make);
    }

    /// Has the ports read the saved databases through `make()`'s reader, made the first time this is called; later calls keep that one.
    pub(crate) fn use_library(&self, make: impl FnOnce() -> ReadSaved) {
        self.saved.get_or_init(make);
    }

    /// The ports reading the saved databases through `read` (the tests change what it answers as another device would).
    #[cfg(test)]
    pub(crate) fn reading_saved(self, read: impl Fn(&str) -> Result<Option<SavedDatabase>, String> + Send + Sync + 'static) -> Self {
        let _ = self.saved.set(Arc::new(read));
        self
    }

    /// The reader a port is started with: the library's, or, before the app has given one, a reader that finds nothing saved.
    fn reader(&self) -> ReadSaved {
        self.saved.get().cloned().unwrap_or_else(|| Arc::new(|_: &str| Ok(None)))
    }

    /// The ports with another time limit for an app's start-up and password (the tests do not wait thirty seconds).
    #[cfg(test)]
    fn signing_in_within(mut self, limit: Duration) -> Self {
        self.sign_in_within = limit;
        self
    }

    /// The ports on `clocks`, looking at their writable windows every `tick` (the tests move clocks of their own, and do not wait a second
    /// for each look).
    #[cfg(test)]
    pub(crate) fn timed_by(mut self, clocks: Clocks, tick: Duration) -> Self {
        self.clocks = clocks;
        self.tick = tick;
        self
    }

    /// How many times the database `id`'s port has looked at its window (the tests wait for a look after they move their clock).
    #[cfg(test)]
    pub(crate) fn ticks(&self, id: &str) -> usize {
        self.port(id).map_or(0, |port| port.ticks.load(std::sync::atomic::Ordering::SeqCst))
    }

    /// The time now, by the ports' wall clock.
    pub(crate) fn now(&self) -> SystemTime {
        (self.clocks.wall)()
    }

    /// The port of the database `id`, provided writes can be unlocked on it now: it locks as prod (`Port::locks_as_prod`), and it runs.
    /// The person is asked to confirm after this, and `unlock` unlocks this port only. It may read the library, so it runs on a blocking
    /// thread.
    pub(crate) fn unlockable(&self, id: &str) -> Result<Unlockable, String> {
        let port = self.port(id).ok_or(NOT_RUNNING)?;
        let prod = port.locks_as_prod();
        port.unlockable(&locked(&port.state), prod)?;
        Ok(Unlockable { port })
    }

    /// Opens the writable window of the port `checked` found for `WRITABLE_WINDOW` from `now`, and answers when it ends, in milliseconds
    /// since the Unix epoch. Until then the connections that come are not locked; the open ones keep their lock. A window that is open
    /// already starts again from `now`. A database that was stopped and started again since runs on another port, which nobody was asked
    /// about, and stays locked; so does one that no longer locks as prod. It may read the library, so it runs on a blocking thread.
    pub fn unlock(&self, checked: &Unlockable, now: SystemTime) -> Result<u64, String> {
        if !self.port(&checked.port.db.id).is_some_and(|port| Arc::ptr_eq(&port, &checked.port)) {
            return Err(STAY_LOCKED.to_string());
        }
        let prod = checked.port.locks_as_prod();
        checked.port.unlock(Moment { wall: now, monotonic: (self.clocks.monotonic)() }, prod).map(millis)
    }

    /// Ends the writable window of the database `id` now, when it is open: new connections are locked, and those that came without the lock
    /// close as soon as they are idle.
    pub fn lock(&self, id: &str) {
        if let Some(port) = self.port(id) {
            port.lock(self.clocks.now());
        }
    }

    /// Closes the connections to the database `id` that carry the lock and are idle, so that their apps connect again (without the lock
    /// while the window is open), and answers how many it closed. One in a transaction, or waiting for an answer, stays.
    pub fn reconnect_locked(&self, id: &str) -> u32 {
        self.port(id).map_or(0, |port| port.reconnect_locked())
    }

    fn port(&self, id: &str) -> Option<Arc<Port>> {
        locked(&self.ports).get(id).cloned()
    }

    fn runtime(&self) -> Result<&tokio::runtime::Runtime, String> {
        self.runtime.get_or_init(PortRuntime::new).as_ref().map(PortRuntime::get).ok_or_else(|| UNAVAILABLE.to_string())
    }

    /// Starts `db`'s port: listens on 127.0.0.1 at its local port (0: one the system picks) and serves the apps that sign in with
    /// `password`. `quit` stops the port when it is cancelled (the broker cancels it when the app quits), and `hold` is kept until the port
    /// has stopped (the broker's registration of `quit`, which keeps the app from quitting without stopping the port). An address that
    /// cannot be had leaves the port failed, with the sentence it answers.
    pub fn start(&self, db: &SavedDatabase, password: Zeroizing<String>, quit: CancelToken, hold: Box<dyn Send>) -> Result<(), String> {
        let Some(number) = db.local_port else { return Err(NO_LOCAL_PORT.to_string()) };
        let upstream = Arc::clone(self.upstream.get().ok_or(UNAVAILABLE)?);
        let runtime = self.runtime()?;
        let port = {
            let mut ports = locked(&self.ports);
            if let Some(busy) = ports.get(&db.id).filter(|port| port.busy()) {
                return Err(busy.busy_sentence());
            }
            if ports.values().filter(|port| port.busy()).count() >= MAX_RUNNING_DATABASES {
                return Err(format!("Lunport runs up to {MAX_RUNNING_DATABASES} databases at once."));
            }
            let port = Arc::new(Port::new(db.clone(), password, quit, self.clocks.clone(), self.reader()));
            ports.insert(db.id.clone(), Arc::clone(&port));
            port
        };
        let listener = match listen(number, runtime) {
            Ok(listener) => listener,
            Err(sentence) => {
                port.failed(&sentence);
                return Err(sentence);
            }
        };
        port.listening(listener.local_addr().map_or(number, |address| address.port()));
        runtime.spawn(serve(port, listener, upstream, self.sign_in_within, self.tick, hold));
        Ok(())
    }

    /// Stops the database `id`'s port: it lets go of its address and closes every connection, those that wait for the person too.
    pub fn stop(&self, id: &str) {
        let port = locked(&self.ports).get(id).cloned();
        if let Some(port) = port {
            port.stop();
        }
    }

    /// The password the database `id`'s port holds now (the tests look whether a port that stopped let go of it).
    #[cfg(test)]
    pub(crate) fn held_password(&self, id: &str) -> Zeroizing<String> {
        locked(&self.ports)[id].password()
    }

    pub fn live(&self, id: &str) -> DatabaseLive {
        locked(&self.ports).get(id).map(|port| port.live()).unwrap_or_default()
    }

    /// The database the port of `id` runs, as it was saved when the port started, while the port starts, runs or stops.
    pub(crate) fn running_database(&self, id: &str) -> Option<SavedDatabase> {
        locked(&self.ports).get(id).filter(|port| port.busy()).map(|port| port.db.clone())
    }

    /// Whether the database `id`'s port is starting, running or stopping here.
    pub fn running(&self, id: &str) -> bool {
        locked(&self.ports).get(id).is_some_and(|port| port.busy())
    }

    /// The database `id` was deleted: what its connections had goes with it. A database that runs is not deleted, so its port stopped
    /// before and keeps nothing else.
    pub(crate) fn release(&self, id: &str) {
        if let Some(upstream) = self.upstream.get() {
            upstream.release(id);
        }
    }

    /// The password the database `id`'s port asks of the connections that come from now on, while the port starts or runs; those that
    /// are open go on. A port that does not run holds no password, and its next start is given the one the keychain holds.
    pub fn set_password(&self, id: &str, password: Zeroizing<String>) {
        let port = locked(&self.ports).get(id).cloned();
        if let Some(port) = port {
            port.set_password(password);
        }
    }

    /// Runs `save` under the edit lock, unless the database `id` runs here: a running database is not changed.
    pub(crate) fn edit<T>(&self, id: &str, save: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        let _editing = self.editing();
        if let Some(port) = locked(&self.ports).get(id).filter(|port| port.busy()) {
            return Err(format!("Stop {} before you change it.", port.db.name));
        }
        save()
    }

    /// Holds off edits: a start reads the saved database and starts it under this, so that no save comes in between.
    pub(crate) fn editing(&self) -> MutexGuard<'_, ()> {
        locked(&self.edits)
    }

    /// The databases that run here although `saved` does not list them any more, to be listed so that they can be stopped. One that does
    /// not run and is not saved is forgotten.
    pub(crate) fn unsaved(&self, saved: &dyn Fn(&str) -> bool) -> Vec<(SavedDatabase, DatabaseLive)> {
        let mut ports = locked(&self.ports);
        ports.retain(|id, port| saved(id) || port.busy());
        ports.iter().filter(|(id, _)| !saved(id)).map(|(_, port)| (port.db.clone(), port.live())).collect()
    }
}

/// A database's port that could be unlocked when `DatabasePorts::unlockable` looked: the person is asked about this one.
pub(crate) struct Unlockable {
    port: Arc<Port>,
}

impl Unlockable {
    /// The name of its database, for the question.
    pub(crate) fn name(&self) -> &str {
        &self.port.db.name
    }
}

/// One database's port.
struct Port {
    /// The database as it was saved when the port started: an edit elsewhere changes nothing that runs, except that a database saved as
    /// prod since then locks the port's next connections (`locks_as_prod`).
    db: SavedDatabase,
    /// Reads the database as it is saved now.
    saved: ReadSaved,
    password: Mutex<Zeroizing<String>>,
    /// Cancelled when the port stops or the app quits: the port closes its connections, and what they wait for (Google's APIs, a question
    /// to the person) gives up.
    quit: CancelToken,
    /// Wakes the port's listener when `stop` cancels `quit`; for the broker's cancel it looks every `QUIT_POLL`.
    woken: Notify,
    /// Taken before `writes` where both are held.
    state: Mutex<PortState>,
    /// How many of its `MAX_PORT_CONNECTIONS` slots are held.
    open: Mutex<usize>,
    /// The clocks its writable window goes by.
    clocks: Clocks,
    writes: Mutex<Writes>,
    /// How many times it looked at its window (`DatabasePorts::ticks`).
    #[cfg(test)]
    ticks: std::sync::atomic::AtomicUsize,
}

struct PortState {
    phase: DatabasePhase,
    port: Option<u16>,
    error: Option<String>,
}

impl Port {
    fn new(db: SavedDatabase, password: Zeroizing<String>, quit: CancelToken, clocks: Clocks, saved: ReadSaved) -> Port {
        Port {
            db,
            saved,
            password: Mutex::new(password),
            quit,
            woken: Notify::new(),
            state: Mutex::new(PortState { phase: DatabasePhase::Starting, port: None, error: None }),
            open: Mutex::new(0),
            clocks,
            writes: Mutex::default(),
            #[cfg(test)]
            ticks: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn live(&self) -> DatabaseLive {
        let state = locked(&self.state);
        let connections = u32::try_from(*locked(&self.open)).unwrap_or(u32::MAX);
        let writable_until_ms = locked(&self.writes).open_until(self.clocks.now()).map(millis);
        DatabaseLive { phase: state.phase, port: state.port, connections, writable_until_ms, error: state.error.clone() }
    }

    fn busy(&self) -> bool {
        locked(&self.state).phase.busy()
    }

    fn busy_sentence(&self) -> String {
        match locked(&self.state).phase {
            DatabasePhase::Stopping => format!("{} is still stopping. Try again in a moment.", self.db.name),
            _ => format!("{} is already running.", self.db.name),
        }
    }

    fn password(&self) -> Zeroizing<String> {
        locked(&self.password).clone()
    }

    /// Asks `password` of the apps that connect from now on, while the port starts or runs. A port that stopped or failed holds no password,
    /// and `forget_password` is the last thing it does with one, so a password written after that would stay: the phase is held while the
    /// password is written, so that it cannot change in between.
    fn set_password(&self, password: Zeroizing<String>) {
        let state = locked(&self.state);
        if matches!(state.phase, DatabasePhase::Starting | DatabasePhase::Running) {
            *locked(&self.password) = password;
        }
    }

    /// It listens on `port`; running, unless it was stopped meanwhile.
    fn listening(&self, port: u16) {
        let mut state = locked(&self.state);
        state.port = Some(port);
        if state.phase == DatabasePhase::Starting {
            state.phase = DatabasePhase::Running;
        }
    }

    fn failed(&self, error: &str) {
        *locked(&self.state) = PortState { phase: DatabasePhase::Error, port: None, error: Some(cut(error)) };
        self.forget_password();
    }

    /// Lets go of its password, wiped as it goes: a port that does not run asks nobody for it.
    fn forget_password(&self) {
        *locked(&self.password) = Zeroizing::new(String::new());
    }

    /// Stops it, and ends its writable window: it closes every connection, and starts locked the next time.
    fn stop(&self) {
        {
            let mut state = locked(&self.state);
            if !state.phase.busy() {
                return;
            }
            state.phase = DatabasePhase::Stopping;
            locked(&self.writes).until = None;
        }
        self.quit.cancel();
        self.woken.notify_one();
    }

    /// Its listener ended (stopped, or the app quits), and so did its writable window.
    fn stopping(&self) {
        let mut state = locked(&self.state);
        if state.phase.busy() {
            state.phase = DatabasePhase::Stopping;
        }
        locked(&self.writes).until = None;
    }

    fn stopped(&self) {
        *locked(&self.state) = PortState { phase: DatabasePhase::Stopped, port: None, error: None };
    }

    /// One of its slots, when one is free.
    fn admit(self: &Arc<Port>) -> Option<Slot> {
        let mut open = locked(&self.open);
        if *open >= MAX_PORT_CONNECTIONS {
            return None;
        }
        *open += 1;
        Some(Slot(Arc::clone(self)))
    }

    /// Whether its connections are locked as prod (`effective_environment`): the database it started with is prod, or the one saved now
    /// is. One that is no longer saved leaves the database it started with to decide, and a library that cannot be read counts as prod, so
    /// that no connection goes unlocked for want of a read. It may read the library, so it runs on a blocking thread.
    fn locks_as_prod(&self) -> bool {
        if self.db.is_prod() {
            return true;
        }
        match (self.saved)(&self.db.id) {
            Ok(Some(saved)) => effective_environment(&saved, Some(&self.db)) == DatabaseEnvironment::Prod,
            Ok(None) => false,
            Err(_) => true,
        }
    }

    /// Whether writes can be unlocked on its database while the port is in `state`, with `prod` read by `locks_as_prod`: a database that
    /// locks as prod, whose port runs.
    fn unlockable(&self, state: &PortState, prod: bool) -> Result<(), String> {
        if !prod {
            Err(ONLY_PROD.to_string())
        } else if state.phase != DatabasePhase::Running {
            Err(NOT_RUNNING.to_string())
        } else {
            Ok(())
        }
    }

    /// Opens its writable window from `now`, and answers when it ends; `prod` is as `unlockable` takes it. A connection that came without
    /// the lock and was to close since an earlier window ended goes on while this one is open. The phase is held meanwhile, so that a port
    /// that stops keeps no window.
    fn unlock(&self, now: Moment, prod: bool) -> Result<SystemTime, String> {
        let state = locked(&self.state);
        self.unlockable(&state, prod)?;
        let until = now.after(WRITABLE_WINDOW);
        let mut writes = locked(&self.writes);
        writes.until = Some(until);
        for connection in writes.connections.values().filter(|connection| !connection.locked) {
            connection.reprieve();
        }
        Ok(until.wall)
    }

    /// Ends its writable window at `now`, when it is open.
    fn lock(&self, now: Moment) {
        let mut writes = locked(&self.writes);
        if let Some(until) = writes.until.take() {
            writes.window_ended(now.earlier(until));
        }
    }

    /// Looks at its window at `now`: when the window has ended, it ends it as `lock` does; and it closes the connections past their time.
    fn tick(&self, now: Moment) {
        {
            let mut writes = locked(&self.writes);
            if let Some(until) = writes.until.filter(|until| until.reached_by(now)) {
                writes.until = None;
                writes.window_ended(until);
            }
            for connection in writes.connections.values() {
                connection.close_if_due(now);
            }
        }
        #[cfg(test)]
        self.ticks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Closes the idle connections that carry the lock, and answers how many.
    fn reconnect_locked(&self) -> u32 {
        let writes = locked(&self.writes);
        let closed = writes.connections.values().filter(|connection| connection.locked && connection.close_if_idle()).count();
        u32::try_from(closed).unwrap_or(u32::MAX)
    }

    /// Registers a connection that is about to pass its start-up message on to Cloud SQL, until the registration is dropped. It carries
    /// the lock unless the port does not lock as prod (`prod`, read by `locks_as_prod` just before) or the window is open now; the window
    /// is held meanwhile, so that it cannot end in between and miss the connection.
    fn register(self: &Arc<Port>, prod: bool) -> Registered {
        let mut writes = locked(&self.writes);
        let lock = prod && writes.open_until(self.clocks.now()).is_none();
        let connection = Arc::new(Connection::new(lock));
        let number = writes.next;
        writes.next += 1;
        writes.connections.insert(number, Arc::clone(&connection));
        Registered { port: Arc::clone(self), number, connection }
    }
}

/// The writable window of a port, and the connections it decides about.
#[derive(Default)]
struct Writes {
    /// When the window ends, while it is open.
    until: Option<Moment>,
    /// The connections whose start-up message goes, or went, to Cloud SQL, by number.
    connections: BTreeMap<u64, Arc<Connection>>,
    next: u64,
}

impl Writes {
    /// When the window ends by the wall clock, provided it is open at `now`.
    fn open_until(&self, now: Moment) -> Option<SystemTime> {
        self.until.filter(|until| !until.reached_by(now)).map(|until| until.on_the_wall(now))
    }

    /// The window ended at `ended`: each connection that came without the lock closes as soon as it is idle, and `CLOSE_UNLOCKED_WITHIN`
    /// after `ended` at the latest.
    fn window_ended(&self, ended: Moment) {
        for connection in self.connections.values().filter(|connection| !connection.locked) {
            connection.close_by(ended.after(CLOSE_UNLOCKED_WITHIN));
        }
    }
}

/// A connection's place among its port's, which it gives up when it is dropped.
struct Registered {
    port: Arc<Port>,
    number: u64,
    connection: Arc<Connection>,
}

impl Drop for Registered {
    fn drop(&mut self) {
        locked(&self.port.writes).connections.remove(&self.number);
    }
}

/// One app's connection as its relay and its port share it.
struct Connection {
    /// Whether it carries Cloud SQL's read-only lock, which it keeps for as long as it lasts.
    locked: bool,
    flow: Mutex<Flow>,
    /// Wakes its relay when it is to close.
    closing: Notify,
}

/// What went through a connection, as far as its closing goes.
#[derive(Default)]
struct Flow {
    /// Follows Cloud SQL's side.
    server: ReadyTracker,
    /// How many times Cloud SQL had said the session is idle (`ReadyTracker::idle_readies`) when the app last sent something.
    sent_after: Option<u64>,
    /// What Cloud SQL sent last is followed already and still on its way to the app: the session is not idle until the app has it, so
    /// that no close cuts an answer off.
    delivering: bool,
    /// When it closes at the latest: the window it came in ended. It closes as soon as it is idle before then.
    close_by: Option<Moment>,
    closed: bool,
}

impl Flow {
    /// Whether the session is idle: Cloud SQL's side is between messages after a ReadyForQuery that said so, the app has all of it, and the
    /// app has sent nothing since. Cloud SQL's side alone does not show a query that was sent and is not answered yet.
    fn idle(&self) -> bool {
        !self.delivering && self.server.idle() && self.sent_after != Some(self.server.idle_readies())
    }
}

impl Connection {
    fn new(locked: bool) -> Connection {
        Connection { locked, flow: Mutex::default(), closing: Notify::new() }
    }

    /// Closes it: its relay ends, and both its sides with it.
    fn close(&self, flow: &mut Flow) {
        if !flow.closed {
            flow.closed = true;
            self.closing.notify_one();
        }
    }

    /// Cloud SQL sent `bytes`, which go on to the app now. They are followed before the app gets them, so that what the app sends after
    /// them counts as sent after them.
    fn from_server(&self, bytes: &[u8]) {
        let mut flow = locked(&self.flow);
        flow.server.feed(bytes);
        flow.delivering = true;
    }

    /// The app got what Cloud SQL sent. Once its window ended, a connection closes as soon as that leaves it idle: a close that came while
    /// the bytes were on their way happens here.
    fn passed_on(&self) {
        let mut flow = locked(&self.flow);
        flow.delivering = false;
        if flow.close_by.is_some() && flow.idle() {
            self.close(&mut flow);
        }
    }

    /// Whether what the app sent goes on to Cloud SQL. Nothing does once the connection closes, nor once its window ended while it is
    /// idle: what the app sent then would start something new, and the connection closes instead.
    fn may_send(&self) -> bool {
        let mut flow = locked(&self.flow);
        if flow.close_by.is_some() && flow.idle() {
            self.close(&mut flow);
        }
        if flow.closed {
            return false;
        }
        flow.sent_after = Some(flow.server.idle_readies());
        true
    }

    /// The window it came in ended: it closes as soon as it is idle, and at `by` at the latest.
    fn close_by(&self, by: Moment) {
        let mut flow = locked(&self.flow);
        flow.close_by = Some(by);
        if flow.idle() {
            self.close(&mut flow);
        }
    }

    /// A window is open again: it goes on.
    fn reprieve(&self) {
        locked(&self.flow).close_by = None;
    }

    /// Closes it when it is past its time at `now`.
    fn close_if_due(&self, now: Moment) {
        let mut flow = locked(&self.flow);
        if flow.close_by.is_some_and(|by| by.reached_by(now)) {
            self.close(&mut flow);
        }
    }

    /// Closes it when it is idle, and answers whether it did.
    fn close_if_idle(&self) -> bool {
        let mut flow = locked(&self.flow);
        let idle = !flow.closed && flow.idle();
        if idle {
            self.close(&mut flow);
        }
        idle
    }
}

/// One of a port's slots, held by a connection from when the port takes it until it closes.
struct Slot(Arc<Port>);

impl Drop for Slot {
    fn drop(&mut self) {
        *locked(&self.0.open) -= 1;
    }
}

/// Listens on 127.0.0.1 at `number` on `runtime`, unless another program takes connections there already.
fn listen(number: u16, runtime: &tokio::runtime::Runtime) -> Result<TcpListener, String> {
    let in_use = || format!("Port {number} is already in use on this computer.");
    // A program that listens on every address (Docker's `-p 5432:5432`, for one) does not make the bind below fail everywhere (on macOS
    // it does not), yet it would still answer the apps that dial `localhost` over IPv6.
    if number != 0 && answers(number) {
        return Err(in_use());
    }
    let could_not = |error: io::Error| format!("Lunport could not open port {number}: {error}.");
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], number))).map_err(|error| match error.kind() {
        io::ErrorKind::AddrInUse => in_use(),
        _ => could_not(error),
    })?;
    listener.set_nonblocking(true).map_err(could_not)?;
    let _entered = runtime.enter();
    TcpListener::from_std(listener).map_err(could_not)
}

/// Whether a program takes connections at `number` on 127.0.0.1 or on ::1 already. A refused connection, one that does not come in time,
/// and a computer without IPv6 say it does not.
fn answers(number: u16) -> bool {
    [IpAddr::V4(Ipv4Addr::LOCALHOST), IpAddr::V6(Ipv6Addr::LOCALHOST)]
        .into_iter()
        .any(|ip| std::net::TcpStream::connect_timeout(&SocketAddr::new(ip, number), PROBE_WITHIN).is_ok())
}

/// Runs a port: takes the apps that connect until the port stops or the app quits, and looks at its writable window every `tick`; then
/// lets go of the address, closes every connection, lets go of what was kept for the database (its password, its certificate) and of
/// `hold`.
async fn serve(port: Arc<Port>, listener: TcpListener, upstream: Arc<dyn Upstream>, sign_in_within: Duration, tick: Duration, hold: Box<dyn Send>) {
    let mut apps = JoinSet::new();
    let mut poll = tokio::time::interval(QUIT_POLL);
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    while !port.quit.is_cancelled() {
        tokio::select! {
            () = port.woken.notified() => {}
            _ = poll.tick() => {}
            _ = ticker.tick() => port.tick(port.clocks.now()),
            accepted = listener.accept() => match accepted {
                Ok((app, _)) => {
                    apps.spawn(serve_app(Arc::clone(&port), app, Arc::clone(&upstream), sign_in_within));
                }
                // Out of file descriptors, or a connection reset before it was taken: the next one is taken in a moment.
                Err(_) => tokio::time::sleep(ACCEPT_PAUSE).await,
            },
            Some(_) = apps.join_next(), if !apps.is_empty() => {}
        }
    }
    port.stopping();
    drop(listener);
    apps.shutdown().await;
    upstream.release(&port.db.id);
    port.forget_password();
    port.stopped();
    drop(hold);
}

/// What an app opened its connection with, once its requests for encryption were answered.
enum Opening {
    Cancel(Vec<u8>),
    Startup(Startup),
}

/// Reads the app's first message, answering `N` to as many as `MAX_ENCRYPTION_REQUESTS` requests for encryption: the connection stays on
/// this computer, and an app that prefers encryption goes on without it.
async fn opening(app: &mut TcpStream) -> io::Result<Opening> {
    let mut refused = 0;
    loop {
        match read_first(app).await? {
            FirstMessage::Ssl | FirstMessage::GssEnc if refused < MAX_ENCRYPTION_REQUESTS => {
                refused += 1;
                app.write_all(b"N").await?;
            }
            FirstMessage::Ssl | FirstMessage::GssEnc => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "The app asked to encrypt the connection more than twice."))
            }
            FirstMessage::Cancel(request) => return Ok(Opening::Cancel(request)),
            FirstMessage::Startup(startup) => return Ok(Opening::Startup(startup)),
        }
    }
}

/// Serves one app: signs it in with the port's password, gets the connection ready upstream, passes its start-up message on and relays
/// the session until either side ends it. Each way this fails ends with an ErrorResponse that says why, unless the app went away or did
/// not sign in within `sign_in_within`.
async fn serve_app(port: Arc<Port>, mut app: TcpStream, upstream: Arc<dyn Upstream>, sign_in_within: Duration) {
    let _ = app.set_nodelay(true);
    let slot = port.admit();
    let deadline = tokio::time::Instant::now() + sign_in_within;
    let startup = match tokio::time::timeout_at(deadline, opening(&mut app)).await {
        Ok(Ok(Opening::Startup(startup))) => startup,
        // A cancel request takes a slot as any connection does: it needs no password, and it dials Cloud SQL. Without one it is closed.
        Ok(Ok(Opening::Cancel(request))) => {
            if slot.is_some() {
                pass_on_cancel(upstream.as_ref(), &port.db.id, &request).await;
            }
            return;
        }
        Ok(Err(error)) => return refuse_unreadable(&mut app, &error).await,
        Err(_) => return,
    };
    let Some(_slot) = slot else {
        return refuse(&mut app, "53300", &format!("{} has reached {MAX_PORT_CONNECTIONS} connections.", label(&port.db.name))).await;
    };
    // An app that asked for a newer protocol, or for protocol options, is told first what Lunport speaks, as a server tells it.
    let (startup, negotiation) = startup.negotiated();
    let asked = async {
        if let Some(negotiation) = &negotiation {
            app.write_all(negotiation).await?;
        }
        app.write_all(&auth_cleartext()).await?;
        read_password(&mut app).await
    };
    let password = match tokio::time::timeout_at(deadline, asked).await {
        Ok(Ok(password)) => password,
        Ok(Err(error)) => return refuse_unreadable(&mut app, &error).await,
        Err(_) => return,
    };
    if !passwords_match(&port.password(), &password) {
        return refuse(&mut app, "28P01", &format!("Wrong password for {}. Copy the password from Lunport.", label(&port.db.name))).await;
    }
    drop(password);
    let (db, quit, preparing, reading) = (port.db.clone(), port.quit.clone(), Arc::clone(&upstream), Arc::clone(&port));
    // Whether the port locks as prod is read once the connection is ready, on the blocking thread: the database may have been saved anew
    // while a grant question waited for the person.
    let ready = tokio::task::spawn_blocking(move || preparing.prepare(&db, &quit).map(|prepared| (prepared, reading.locks_as_prod())));
    let (prepared, prod) = match ready.await {
        Ok(Ok(ready)) => ready,
        Ok(Err(not_ready)) => return refuse(&mut app, not_ready.sqlstate(), &cut(not_ready.sentence())).await,
        Err(_) => return refuse(&mut app, "08006", "Lunport could not get the connection ready.").await,
    };
    // Whether the session carries the lock is decided here, and the port follows the connection from here on.
    let registered = port.register(prod);
    let startup = startup.with_user(&prepared.iam_user);
    let startup = if registered.connection.locked { startup.with_read_only_lock() } else { startup };
    let message = startup.encode();
    if message.len() - 4 > MAX_CLOUD_SQL_STARTUP_BYTES {
        return refuse(&mut app, "08P01", TOO_LONG).await;
    }
    let connection = port.db.connection_name();
    let Dialling { material, stream } = upstream.connect(&port.db.id, Some(prepared.material));
    // What failed before Cloud SQL answered is not dialled with again: in TLS 1.3 a refused certificate shows only then.
    let forget = || {
        if let Some(material) = material {
            upstream.forget(&port.db.id, material);
        }
    };
    let mut server = match stream.await {
        Ok(server) => server,
        Err(error) => {
            forget();
            return refuse(&mut app, "08006", &unreachable(&connection, &error)).await;
        }
    };
    let answer = async {
        server.write_all(&message).await?;
        server.flush().await?;
        read_server_auth(&mut server).await
    };
    let answered = match tokio::time::timeout(SERVER_ANSWER_WITHIN, answer).await {
        Ok(answered) => answered,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, format!("Cloud SQL did not answer within {} seconds.", SERVER_ANSWER_WITHIN.as_secs()))),
    };
    let (auth, first) = match answered {
        Ok(answer) => answer,
        Err(error) => {
            forget();
            return refuse(&mut app, "08006", &unreachable(&connection, &error)).await;
        }
    };
    match auth {
        ServerAuth::Ok => {
            if app.write_all(&first).await.is_ok() {
                let (from_app, to_app) = app.into_split();
                relay(from_app, to_app, server, &first, &registered.connection).await;
            }
        }
        ServerAuth::NeedsPassword => {
            let sentence = format!("Cloud SQL asked for a database password. Turn on IAM database authentication for {connection}.");
            refuse(&mut app, "28000", &sentence).await;
        }
        // Cloud SQL refused the session and said why: the app gets its words. A refused sign-in (SQLSTATE class 28) can be the
        // certificate's, whose token Cloud SQL no longer takes: the next connection gets new material.
        ServerAuth::Error { sqlstate } => {
            if sqlstate.is_some_and(|code| code.starts_with("28")) {
                forget();
            }
            let _ = app.write_all(&first).await;
            let _ = app.shutdown().await;
        }
    }
}

/// Ends the app's connection with a fatal ErrorResponse.
async fn refuse(app: &mut TcpStream, sqlstate: &str, message: &str) {
    let _ = app.write_all(&error_response(sqlstate, message)).await;
    let _ = app.shutdown().await;
}

/// Ends the connection of an app that sent what no app sends with a sentence about it; one that went away is only closed.
async fn refuse_unreadable(app: &mut TcpStream, error: &io::Error) {
    if error.kind() == io::ErrorKind::InvalidData {
        refuse(app, "08P01", &cut(&error.to_string())).await;
    }
}

/// Passes the app's cancel request on to Cloud SQL as it came, and waits for Cloud SQL to close that connection, as it does once it took
/// the request. The app's connection closes after it, which tells the app that the request was handled.
async fn pass_on_cancel(upstream: &dyn Upstream, db_id: &str, request: &[u8]) {
    let passed = async {
        let mut server = upstream.connect(db_id, None).stream.await?;
        server.write_all(request).await?;
        server.flush().await?;
        let mut rest = [0u8; 64];
        while server.read(&mut rest).await? > 0 {}
        io::Result::Ok(())
    };
    let _ = tokio::time::timeout(CANCEL_WITHIN, passed).await;
}

/// Relays a signed-in session between the app's two halves and Cloud SQL until either side ends it or the port closes `connection`. Both
/// sides are followed for whether the session is idle: Cloud SQL's from its first answer (`first`, passed on already) on, before the app
/// gets what it sends, and the app's before what it sends goes on. A close for idleness waits until the app has what Cloud SQL sent.
async fn relay(mut from_app: impl AsyncRead + Unpin, mut to_app: impl AsyncWrite + Unpin, server: BoxStream, first: &[u8], connection: &Connection) {
    connection.from_server(first);
    connection.passed_on();
    let (mut from_server, mut to_server) = tokio::io::split(server);
    let upward = async {
        let mut buffer = vec![0u8; RELAY_BUFFER_BYTES];
        loop {
            let read = match from_app.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            if !connection.may_send() {
                return;
            }
            if to_server.write_all(&buffer[..read]).await.is_err() || to_server.flush().await.is_err() {
                break;
            }
        }
        let _ = to_server.shutdown().await;
    };
    let downward = async {
        let mut buffer = vec![0u8; RELAY_BUFFER_BYTES];
        loop {
            let read = match from_server.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            connection.from_server(&buffer[..read]);
            if to_app.write_all(&buffer[..read]).await.is_err() {
                break;
            }
            connection.passed_on();
        }
        let _ = to_app.shutdown().await;
    };
    tokio::select! {
        () = upward => {}
        () = downward => {}
        () = connection.closing.notified() => {}
    }
}

/// The sentence an app is refused with when Cloud SQL could not be reached, for `error`.
fn unreachable(connection: &str, error: &io::Error) -> String {
    let reason = match error.kind() {
        io::ErrorKind::UnexpectedEof => "Cloud SQL closed the connection.".to_string(),
        _ => error.to_string(),
    };
    let reason = reason.trim();
    let end = if reason.ends_with('.') { "" } else { "." };
    cut(&format!("Lunport could not reach {connection}: {reason}{end}"))
}

/// `time` in milliseconds since the Unix epoch, as the page reads it.
fn millis(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

/// `text` as an error sentence carries it: printable, and at most `ERROR_CHARS` characters.
fn cut(text: &str) -> String {
    printable(text).chars().take(ERROR_CHARS).collect()
}

pub(super) fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[path = "database_ports_tests.rs"]
pub(crate) mod tests;
