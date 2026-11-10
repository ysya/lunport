//! The local port of a saved database: Lunport listens on 127.0.0.1 for the apps on this computer (DataGrip, psql) and signs them in to
//! Cloud SQL with the person's Google account. An app signs in to the port with the password Lunport made for the database. Lunport then
//! gets what the connection needs from Google (the Privileged Access Manager grant the database asks for, and a client certificate Cloud
//! SQL signs), dials the instance over TLS, passes the app's start-up message on as the IAM database user, with Cloud SQL's read-only lock
//! for a prod database, and relays the session.
//!
//! The ports run on one small runtime of their own. What blocks (Google's APIs, a grant question that waits for the person) runs on its
//! blocking threads. Each port is registered with the broker while it runs, so quitting the app stops it.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use futures_util::future::BoxFuture;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tauri::Manager;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

use super::auth::{printable, Owner};
use super::auth_window::{NativeOwner, TauriAuthSurface};
use super::broker::Broker;
use super::connect::CancelToken;
use super::database_access::{fetch_material, grant_state, obtain_grant, Grace, GrantState};
use super::databases::{DatabaseLive, DatabasePhase};
use super::grants::GrantGates;
use super::pgwire::{auth_cleartext, error_response, passwords_match, read_first, read_password, read_server_auth, FirstMessage, ReadyTracker, ServerAuth, Startup};
use super::tunnels::snapshot;
use crate::error::AppError;
use crate::gcp::cloudsql::SqlAdmin;
use crate::gcp::cloudsql_tls::{self, client_config, server_name, ServerIdentity};
use crate::gcp::rest::GcpClient;
use crate::state::AppState;
use crate::sync::databases::SavedDatabase;
use crate::sync::env::Keychain;
use crate::sync::records_v3::SyncStateV3;

/// The most connections one port has open at once.
pub const MAX_PORT_CONNECTIONS: usize = 64;
/// The most databases that run at once on this device.
pub const MAX_RUNNING_DATABASES: usize = 16;
/// How long before a client certificate stops being useful a connection gets a new one.
pub const REFRESH_AHEAD: Duration = Duration::from_secs(4 * 60);

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
/// How long a check that a grant is held is trusted at most.
const GRANT_RECHECK: Duration = Duration::from_secs(5 * 60);
/// How often a port looks whether the app is quitting (the broker cancels its token).
const QUIT_POLL: Duration = Duration::from_millis(250);
/// How long a port waits after a connection it could not take before it takes the next one.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// How long a cancel request may take to reach Cloud SQL and be taken.
const CANCEL_WITHIN: Duration = Duration::from_secs(10);
const RELAY_BUFFER_BYTES: usize = 16 * 1024;
/// How many random bytes a port's password is made of.
const PASSWORD_BYTES: usize = 24;
/// The most characters of an error sentence, as a tunnel's.
const ERROR_CHARS: usize = 512;
const TOO_LONG: &str = "The connection settings are too long for Cloud SQL. Remove some options and connect again.";
const UNAVAILABLE: &str = "Lunport's database service is unavailable. Restart Lunport and try again.";

/// A byte stream both ways: the connection to Cloud SQL as the port relays it.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
pub type BoxStream = Box<dyn Duplex>;

/// Where a port's connections reach Cloud SQL from.
pub(crate) trait Upstream: Send + Sync {
    /// Gets what a connection to `db` needs (the grant it asks for, the connection material) and answers the database user the connection
    /// signs in as; an error is the sentence the app is refused with. It blocks (Google's APIs, a question that waits for the person), so the
    /// port calls it on a blocking thread. `cancel` is set when the port stops.
    fn prepare(&self, db: &SavedDatabase, cancel: &CancelToken) -> Result<String, String>;
    /// Dials the instance of the database `db_id` with the material `prepare` got for it.
    fn connect(&self, db_id: &str) -> Dialling;
    /// A connection to `db_id` dialled with `material` failed before Cloud SQL answered its start-up message (in TLS 1.3 a refused client
    /// certificate shows only then): that material is not used again, and the next connection gets new material. Newer material that
    /// another connection got meanwhile stays.
    fn forget(&self, db_id: &str, material: u64);
    /// The database `db_id` stopped, or was deleted: everything kept for it goes, its certificate and the key that was made for it too.
    fn release(&self, db_id: &str);
}

/// A connection to an instance under way.
pub(crate) struct Dialling {
    /// Which of the database's material it dials with, for `Upstream::forget`; `None` when there was none to dial with.
    pub material: Option<u64>,
    pub stream: BoxFuture<'static, io::Result<BoxStream>>,
}

// ---- The Cloud SQL upstream ----

/// Makes the owner that asks the person on behalf of a connection that `cancel` cancels.
type MakeOwner = Arc<dyn Fn(&CancelToken) -> Box<dyn Owner + Send> + Send + Sync>;
/// Dials an instance: its public address, the TLS configuration of the connection, and the name its certificate must be made out to.
type Dialer = Arc<dyn Fn(IpAddr, Arc<ClientConfig>, ServerName<'static>) -> BoxFuture<'static, io::Result<BoxStream>> + Send + Sync>;

/// How the app's ports reach Cloud SQL. The grant a database asks for is requested through the gates hosts use, so that a host and a
/// database that need the same grant ask the person once; the connection material comes from the Cloud SQL Admin API. Both are kept for a
/// database's next connections while they last: a check that the grant is held for five minutes at most and never past the grant's end,
/// the material until `REFRESH_AHEAD` before its certificate stops being useful. Both are for the Google account the connections sign in
/// as, and go when it changes; a grant that ended takes the material had under it along.
pub(crate) struct CloudSqlUpstream {
    gcp: Arc<dyn GcpClient>,
    sql: Arc<dyn SqlAdmin>,
    gates: Arc<GrantGates>,
    make_owner: MakeOwner,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    /// gcloud's active account as it is now, which a database saved without an account signs in as.
    active_account: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    /// The library as it is now, whose grant memory a grant question starts from.
    library: Arc<dyn Fn() -> Result<SyncStateV3, String> + Send + Sync>,
    /// Remembers a grant the person asked for: the entitlement's full name, the justification and the length in seconds.
    remember: Arc<dyn Fn(&str, &str, u32) + Send + Sync>,
    dial: Dialer,
    /// What each database's connections share, by the database's id.
    routes: Mutex<HashMap<String, Arc<Route>>>,
    /// The number of the next material fetched, counted from 1.
    generations: AtomicU64,
}

/// What the connections to one database, as it was saved, share. A database saved anew (another account, instance or grant check) gets a
/// route of its own: a connection still on its way with the route before cannot leave anything in it.
struct Route {
    database: SavedDatabase,
    /// Held while the material is fetched, so that connections that start together share one fetch.
    fetching: Mutex<()>,
    kept: Mutex<Kept>,
}

/// What was had for a database, kept for its next connections.
#[derive(Default)]
struct Kept {
    grant: Option<CheckedGrant>,
    dial: Option<Dial>,
    /// The Google account of the last certificate, as the token source resolved it.
    account: Option<String>,
}

impl Kept {
    /// Lets go of what was had for another account than `account`, the one the connections sign in as now (`None`: gcloud has no active
    /// account, and the token source falls back to its default credentials).
    fn keep_for(&mut self, account: &Option<String>) {
        let other = self.grant.as_ref().is_some_and(|check| check.for_account != *account) || self.dial.as_ref().is_some_and(|dial| dial.for_account != *account);
        if other {
            *self = Kept::default();
        }
    }
}

/// A check that found the grant held. One that found it given moments before is not kept: every connection checks such a grant again, so
/// that the time Google is given to see it ends when the grant is no longer that fresh.
struct CheckedGrant {
    /// The account the connections signed in as when it was checked.
    for_account: Option<String>,
    until: Option<SystemTime>,
    checked_at: SystemTime,
}

impl CheckedGrant {
    /// Whether the check still stands at `now`: it is younger than `GRANT_RECHECK`, and the grant has not reached its end.
    fn stands(&self, now: SystemTime) -> bool {
        now < self.checked_at + GRANT_RECHECK && self.until.is_none_or(|until| now < until)
    }
}

/// What a connection dials the instance with.
struct Dial {
    /// Which material this is: a connection that failed with it takes back this one only.
    generation: u64,
    /// The account the connections signed in as when it was fetched.
    for_account: Option<String>,
    iam_user: String,
    /// When the certificate stops being useful (`EphemeralCert::expires_at`).
    expires_at: SystemTime,
    ip: IpAddr,
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}

impl CloudSqlUpstream {
    /// The upstream of the app's ports: Google's APIs through the app's clients, the broker's grant gates, a person's questions in
    /// Lunport's windows (a person starts a port, as a person starts a tunnel), and this device's grant memory.
    pub(crate) fn for_app(app: &tauri::AppHandle, broker: &Broker) -> CloudSqlUpstream {
        let state = app.state::<AppState>();
        let hub = Arc::clone(&state.session.auth_questions);
        let requests = AtomicU64::new(0);
        let (for_owner, for_library, for_memory) = (app.clone(), app.clone(), app.clone());
        CloudSqlUpstream {
            gcp: state.gcp.clone(),
            sql: Arc::clone(&state.sqladmin),
            gates: broker.grants(),
            make_owner: Arc::new(move |cancel: &CancelToken| -> Box<dyn Owner + Send> {
                Box::new(NativeOwner {
                    ai: None,
                    hub: Arc::clone(&hub),
                    surface: Arc::new(TauriAuthSurface { app: for_owner.clone() }),
                    request_id: format!("database-{}", requests.fetch_add(1, Ordering::Relaxed)),
                    cancel: cancel.clone(),
                })
            }),
            now: Arc::new(SystemTime::now),
            // Two small files of gcloud's, read for every connection: what the token source signs in as when it is given no account.
            active_account: Arc::new(|| crate::gcp::auth::active_account(&super::transports::gcloud_config_dir())),
            library: Arc::new(move || snapshot(&for_library)),
            // What the person asked for is remembered for the entitlement on this device, as for a host; a memory that cannot be written
            // does not fail the connection.
            remember: Arc::new(move |name: &str, justification: &str, duration_secs: u32| {
                let _ = crate::sync::engine::with_env(&for_memory, |env| {
                    let now = env.now();
                    crate::sync::record_runtime::mutate_records(env, |state| {
                        Ok(crate::sync::pam_records::remember(state, name, justification, duration_secs, None, now).unwrap_or_else(|| state.clone()))
                    })?;
                    env.events.wake();
                    Ok::<_, AppError>(())
                });
            }),
            dial: Arc::new(|ip: IpAddr, config: Arc<ClientConfig>, name: ServerName<'static>| -> BoxFuture<'static, io::Result<BoxStream>> {
                Box::pin(async move { cloudsql_tls::dial(ip, config, name).await.map(|stream| Box::new(stream) as BoxStream) })
            }),
            routes: Mutex::default(),
            generations: AtomicU64::new(1),
        }
    }

    /// What `db`'s connections share: a new route when `db` was saved anew since the last one.
    fn route(&self, db: &SavedDatabase) -> Arc<Route> {
        let mut routes = locked(&self.routes);
        if let Some(route) = routes.get(&db.id).filter(|route| route.database == *db) {
            return Arc::clone(route);
        }
        let route = Arc::new(Route { database: db.clone(), fetching: Mutex::new(()), kept: Mutex::default() });
        routes.insert(db.id.clone(), Arc::clone(&route));
        route
    }

    /// Whether the grant `db` asks for is held for `account`; PAM is asked when the last check no longer stands. When none is, the material
    /// had under the grant that ended goes, and the person is asked for a grant in Lunport's window. Answers whether the grant was given
    /// moments ago.
    fn grant(&self, db: &SavedDatabase, route: &Route, account: &Option<String>, cancel: &CancelToken) -> Result<bool, String> {
        if db.pam.is_none() {
            return Ok(false);
        }
        let now = (self.now)();
        if locked(&route.kept).grant.as_ref().is_some_and(|check| check.for_account == *account && check.stands(now)) {
            return Ok(false);
        }
        match grant_state(self.gcp.as_ref(), db, now)? {
            GrantState::NotNeeded => Ok(false),
            GrantState::Held { recent, until } => {
                locked(&route.kept).grant = (!recent).then(|| CheckedGrant { for_account: account.clone(), until, checked_at: now });
                Ok(recent)
            }
            GrantState::Needed => {
                {
                    let mut kept = locked(&route.kept);
                    kept.grant = None;
                    kept.dial = None;
                }
                let library = (self.library)()?;
                let owner = (self.make_owner)(cancel);
                let remember = |name: &str, justification: &str, duration_secs: u32| (self.remember)(name, justification, duration_secs);
                obtain_grant(&self.gates, self.gcp.as_ref(), owner.as_ref(), &library, db, &remember, cancel)?;
                Ok(true)
            }
        }
    }

    /// The database user of `db`'s connections as `account`, with the material to dial it kept until `REFRESH_AHEAD` before its
    /// certificate stops being useful, and fetched anew after that (`recent_grant`: the grant it relies on was given moments ago). Also
    /// answers whether the new certificate is for another account than the last one although `account` reads the same: the token source's
    /// credentials changed under it, and the grant was checked for the other account.
    fn material(&self, db: &SavedDatabase, route: &Route, account: &Option<String>, recent_grant: bool, cancel: &CancelToken) -> Result<(String, bool), String> {
        let _fetching = locked(&route.fetching);
        let usable = |dial: &&Dial| dial.for_account == *account && (self.now)() + REFRESH_AHEAD < dial.expires_at;
        if let Some(dial) = locked(&route.kept).dial.as_ref().filter(usable) {
            return Ok((dial.iam_user.clone(), false));
        }
        let material = fetch_material(self.sql.as_ref(), db, recent_grant, Grace::default(), cancel)?;
        let identity = ServerIdentity { dns_name: material.settings.dns_name.clone(), project: db.project.clone(), instance: db.instance.clone() };
        let config = client_config(&material.settings, &material.cert, &material.key, &identity)?;
        let ip = material.settings.public_ip.ok_or_else(|| format!("{} has no public IP.", db.connection_name()))?;
        let mut kept = locked(&route.kept);
        let other_account = kept.account.as_ref().is_some_and(|before| *before != material.cert.account);
        if other_account {
            kept.grant = None;
        }
        kept.account = Some(material.cert.account.clone());
        kept.dial = Some(Dial {
            generation: self.generations.fetch_add(1, Ordering::Relaxed),
            for_account: account.clone(),
            iam_user: material.iam_user.clone(),
            expires_at: material.cert.expires_at,
            ip,
            config,
            name: server_name(&identity),
        });
        Ok((material.iam_user.clone(), other_account))
    }
}

impl Upstream for CloudSqlUpstream {
    fn prepare(&self, db: &SavedDatabase, cancel: &CancelToken) -> Result<String, String> {
        let route = self.route(db);
        // The account the connection signs in as: the database's own, else gcloud's active one, which the person can switch at any time.
        let account = db.account.clone().or_else(|| (self.active_account)());
        locked(&route.kept).keep_for(&account);
        let mut checked_for_new_account = false;
        loop {
            let recent_grant = self.grant(db, &route, &account, cancel)?;
            let (iam_user, other_account) = self.material(db, &route, &account, recent_grant, cancel)?;
            // A certificate for another account than the last one is used once the grant was checked for its account.
            if other_account && db.pam.is_some() && !checked_for_new_account {
                checked_for_new_account = true;
                continue;
            }
            return Ok(iam_user);
        }
    }

    fn connect(&self, db_id: &str) -> Dialling {
        let route = locked(&self.routes).get(db_id).cloned();
        let target = route.and_then(|route| locked(&route.kept).dial.as_ref().map(|dial| (dial.generation, dial.ip, Arc::clone(&dial.config), dial.name.clone())));
        match target {
            Some((generation, ip, config, name)) => Dialling { material: Some(generation), stream: (self.dial)(ip, config, name) },
            None => Dialling {
                material: None,
                stream: Box::pin(async { Err(io::Error::new(io::ErrorKind::NotFound, "no certificate is ready for it. Connect again.")) }),
            },
        }
    }

    fn forget(&self, db_id: &str, material: u64) {
        if let Some(route) = locked(&self.routes).get(db_id) {
            let mut kept = locked(&route.kept);
            if kept.dial.as_ref().is_some_and(|dial| dial.generation == material) {
                kept.dial = None;
            }
        }
    }

    fn release(&self, db_id: &str) {
        // A connection still on its way keeps the route it started with; what it gets goes with it.
        locked(&self.routes).remove(db_id);
    }
}

// ---- Passwords ----

/// The keychain account that holds the password of the database `id`'s port.
pub(crate) fn password_account(id: &str) -> String {
    format!("database:port-password:{id}")
}

/// The password of the database `id`'s port: the one `keychain` holds, else a new one, stored before it is answered. A new password is
/// `PASSWORD_BYTES` random bytes as URL-safe base64 without padding, 32 characters an app takes as they are, in a connection URL too.
pub(crate) fn ensure_password(keychain: &dyn Keychain, id: &str) -> Result<Zeroizing<String>, String> {
    let account = password_account(id);
    let stored = keychain.get(&account).map_err(|error| format!("The database's password could not be read from the keychain: {error}"))?;
    if let Some(stored) = stored.filter(|stored| !stored.is_empty()) {
        return Ok(Zeroizing::new(stored));
    }
    let mut bytes = Zeroizing::new([0u8; PASSWORD_BYTES]);
    getrandom::fill(&mut bytes[..]).map_err(|_| "Could not make a password for the database.".to_string())?;
    let password = Zeroizing::new(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[..]));
    keychain.set(&account, &password).map_err(|error| format!("The database's password could not be saved in the keychain: {error}"))?;
    Ok(password)
}

// ---- The ports ----

/// The local ports of the saved databases this device runs.
pub(crate) struct DatabasePorts {
    upstream: OnceLock<Arc<dyn Upstream>>,
    /// Made when the first port starts; `None` when it could not be made.
    runtime: OnceLock<Option<PortRuntime>>,
    /// Held by an edit of a saved database, and by a start while it reads the database it starts: the two do not interleave.
    edits: Mutex<()>,
    ports: Mutex<BTreeMap<String, Arc<Port>>>,
    sign_in_within: Duration,
}

impl Default for DatabasePorts {
    fn default() -> Self {
        DatabasePorts { upstream: OnceLock::new(), runtime: OnceLock::new(), edits: Mutex::new(()), ports: Mutex::default(), sign_in_within: SIGN_IN_WITHIN }
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
    pub fn new(upstream: Arc<dyn Upstream>) -> Self {
        let ports = DatabasePorts::default();
        let _ = ports.upstream.set(upstream);
        ports
    }

    /// Has the ports reach Cloud SQL through `make()`'s upstream, made the first time this is called; later calls keep that one.
    pub(crate) fn use_upstream(&self, make: impl FnOnce() -> Arc<dyn Upstream>) {
        self.upstream.get_or_init(make);
    }

    /// The ports with another time limit for an app's start-up and password (the tests do not wait thirty seconds).
    #[cfg(test)]
    fn signing_in_within(mut self, limit: Duration) -> Self {
        self.sign_in_within = limit;
        self
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
            let port = Arc::new(Port::new(db.clone(), password, quit));
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
        runtime.spawn(serve(port, listener, upstream, self.sign_in_within, hold));
        Ok(())
    }

    /// Stops the database `id`'s port: it lets go of its address and closes every connection, those that wait for the person too.
    pub fn stop(&self, id: &str) {
        let port = locked(&self.ports).get(id).cloned();
        if let Some(port) = port {
            port.stop();
        }
    }

    pub fn live(&self, id: &str) -> DatabaseLive {
        locked(&self.ports).get(id).map(|port| port.live()).unwrap_or_default()
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

    /// The password the database `id`'s port asks of the connections that come from now on; those that are open go on.
    pub fn set_password(&self, id: &str, password: Zeroizing<String>) {
        if let Some(port) = locked(&self.ports).get(id) {
            *locked(&port.password) = password;
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

/// One database's port.
struct Port {
    /// The database as it was saved when the port started: an edit elsewhere changes nothing that runs.
    db: SavedDatabase,
    password: Mutex<Zeroizing<String>>,
    /// Cancelled when the port stops or the app quits: the port closes its connections, and what they wait for (Google's APIs, a question
    /// to the person) gives up.
    quit: CancelToken,
    /// Wakes the port's listener when `stop` cancels `quit`; for the broker's cancel it looks every `QUIT_POLL`.
    woken: Notify,
    state: Mutex<PortState>,
    /// How many of its `MAX_PORT_CONNECTIONS` slots are held.
    open: Mutex<usize>,
}

struct PortState {
    phase: DatabasePhase,
    port: Option<u16>,
    error: Option<String>,
}

impl Port {
    fn new(db: SavedDatabase, password: Zeroizing<String>, quit: CancelToken) -> Port {
        Port {
            db,
            password: Mutex::new(password),
            quit,
            woken: Notify::new(),
            state: Mutex::new(PortState { phase: DatabasePhase::Starting, port: None, error: None }),
            open: Mutex::new(0),
        }
    }

    fn live(&self) -> DatabaseLive {
        let state = locked(&self.state);
        let connections = u32::try_from(*locked(&self.open)).unwrap_or(u32::MAX);
        DatabaseLive { phase: state.phase, port: state.port, connections, writable_until_ms: None, error: state.error.clone() }
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

    fn stop(&self) {
        {
            let mut state = locked(&self.state);
            if !state.phase.busy() {
                return;
            }
            state.phase = DatabasePhase::Stopping;
        }
        self.quit.cancel();
        self.woken.notify_one();
    }

    /// Its listener ended (stopped, or the app quits).
    fn stopping(&self) {
        let mut state = locked(&self.state);
        if state.phase.busy() {
            state.phase = DatabasePhase::Stopping;
        }
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
}

/// One of a port's slots, held by a connection from when the port takes it until it closes.
struct Slot(Arc<Port>);

impl Drop for Slot {
    fn drop(&mut self) {
        *locked(&self.0.open) -= 1;
    }
}

/// Listens on 127.0.0.1 at `number` on `runtime`.
fn listen(number: u16, runtime: &tokio::runtime::Runtime) -> Result<TcpListener, String> {
    let could_not = |error: io::Error| format!("Lunport could not open port {number}: {error}.");
    let listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], number))).map_err(|error| match error.kind() {
        io::ErrorKind::AddrInUse => format!("Port {number} is already in use on this computer."),
        _ => could_not(error),
    })?;
    listener.set_nonblocking(true).map_err(could_not)?;
    let _entered = runtime.enter();
    TcpListener::from_std(listener).map_err(could_not)
}

/// Runs a port: takes the apps that connect until the port stops or the app quits, then lets go of the address, closes every connection,
/// lets go of what was kept for the database (its password, its certificate) and of `hold`.
async fn serve(port: Arc<Port>, listener: TcpListener, upstream: Arc<dyn Upstream>, sign_in_within: Duration, hold: Box<dyn Send>) {
    let mut apps = JoinSet::new();
    let mut poll = tokio::time::interval(QUIT_POLL);
    while !port.quit.is_cancelled() {
        tokio::select! {
            () = port.woken.notified() => {}
            _ = poll.tick() => {}
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
        // A cancel request is passed on however many connections are open, as PostgreSQL takes one: it is over at once, and it may be the
        // way out of a query that holds a slot.
        Ok(Ok(Opening::Cancel(request))) => return pass_on_cancel(upstream.as_ref(), &port.db.id, &request).await,
        Ok(Err(error)) => return refuse_unreadable(&mut app, &error).await,
        Err(_) => return,
    };
    let Some(_slot) = slot else {
        return refuse(&mut app, "53300", &format!("{} has reached {MAX_PORT_CONNECTIONS} connections.", port.db.name)).await;
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
        return refuse(&mut app, "28P01", &format!("Wrong password for {}. Copy the password from Lunport.", port.db.name)).await;
    }
    drop(password);
    let (db, quit, preparing) = (port.db.clone(), port.quit.clone(), Arc::clone(&upstream));
    let iam_user = match tokio::task::spawn_blocking(move || preparing.prepare(&db, &quit)).await {
        Ok(Ok(iam_user)) => iam_user,
        Ok(Err(sentence)) => return refuse(&mut app, "28000", &cut(&sentence)).await,
        Err(_) => return refuse(&mut app, "28000", "Lunport could not get the connection ready.").await,
    };
    let startup = startup.with_user(&iam_user);
    let startup = if locks(&port.db) { startup.with_read_only_lock() } else { startup };
    let message = startup.encode();
    if message.len() - 4 > MAX_CLOUD_SQL_STARTUP_BYTES {
        return refuse(&mut app, "08P01", TOO_LONG).await;
    }
    let connection = port.db.connection_name();
    let Dialling { material, stream } = upstream.connect(&port.db.id);
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
                relay(app, server, &first).await;
            }
        }
        ServerAuth::NeedsPassword => {
            let sentence = format!("Cloud SQL asked for a database password. Turn on IAM database authentication for {connection}.");
            refuse(&mut app, "28000", &sentence).await;
        }
        // Cloud SQL refused the session and said why: the app gets its words.
        ServerAuth::Error => {
            let _ = app.write_all(&first).await;
            let _ = app.shutdown().await;
        }
    }
}

/// Whether a new connection to `db` gets Cloud SQL's read-only lock: every connection to a prod database does, since writes through the
/// port cannot be unlocked.
fn locks(db: &SavedDatabase) -> bool {
    db.is_prod()
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
        let mut server = upstream.connect(db_id).stream.await?;
        server.write_all(request).await?;
        server.flush().await?;
        let mut rest = [0u8; 64];
        while server.read(&mut rest).await? > 0 {}
        io::Result::Ok(())
    };
    let _ = tokio::time::timeout(CANCEL_WITHIN, passed).await;
}

/// Relays a signed-in session both ways until either side ends it. The server's side feeds a `ReadyTracker`, from Cloud SQL's first
/// answer (`first`, passed on already) on, which follows whether the session is idle.
async fn relay(app: TcpStream, server: BoxStream, first: &[u8]) {
    let mut tracker = ReadyTracker::default();
    tracker.feed(first);
    let (mut from_app, mut to_app) = app.into_split();
    let (mut from_server, mut to_server) = tokio::io::split(server);
    let upward = async {
        let _ = tokio::io::copy(&mut from_app, &mut to_server).await;
        let _ = to_server.shutdown().await;
    };
    let downward = async {
        let mut buffer = vec![0u8; RELAY_BUFFER_BYTES];
        loop {
            let read = match from_server.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            tracker.feed(&buffer[..read]);
            if to_app.write_all(&buffer[..read]).await.is_err() {
                break;
            }
        }
        let _ = to_app.shutdown().await;
    };
    tokio::select! {
        () = upward => {}
        () = downward => {}
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

/// `text` as an error sentence carries it: printable, and at most `ERROR_CHARS` characters.
fn cut(text: &str) -> String {
    printable(text).chars().take(ERROR_CHARS).collect()
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[path = "database_ports_tests.rs"]
pub(crate) mod tests;
